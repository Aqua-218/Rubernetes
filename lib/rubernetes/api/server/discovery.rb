# frozen_string_literal: true

require_relative "../version_priority"

module Rubernetes
  module API
    class Server
      # What the server serves and how it says so: /version, /api, /apis, the
      # per-group and per-version documents, aggregated discovery, and the
      # runtime-config and feature-gate rules that decide which resources are on.
      module Discovery
        PINNED_VERSION_PRIORITY = API::PINNED_VERSION_PRIORITY

        # The resources a feature gate guards (DEFAULT_FEATURE_GATES and the
        # pinned corpus say which gates are on).
        DEFAULT_DISABLED_GATES_BY_GVR = {
          ["admissionregistration.k8s.io", "v1alpha1", "mutatingadmissionpolicies"] => "MutatingAdmissionPolicy",
          ["admissionregistration.k8s.io", "v1alpha1", "mutatingadmissionpolicybindings"] => "MutatingAdmissionPolicy",
          ["admissionregistration.k8s.io", "v1beta1", "mutatingadmissionpolicies"] => "MutatingAdmissionPolicy",
          ["admissionregistration.k8s.io", "v1beta1", "mutatingadmissionpolicybindings"] => "MutatingAdmissionPolicy",
          ["certificates.k8s.io", "v1alpha1", "clustertrustbundles"] => "ClusterTrustBundle",
          ["certificates.k8s.io", "v1beta1", "clustertrustbundles"] => "ClusterTrustBundle",
          ["certificates.k8s.io", "v1beta1", "podcertificaterequests"] => "PodCertificateRequest",
          ["coordination.k8s.io", "v1alpha2", "leasecandidates"] => "CoordinatedLeaderElection",
          ["coordination.k8s.io", "v1beta1", "leasecandidates"] => "CoordinatedLeaderElection",
          ["networking.k8s.io", "v1beta1", "ipaddresses"] => "MultiCIDRServiceAllocator",
          ["networking.k8s.io", "v1beta1", "servicecidrs"] => "MultiCIDRServiceAllocator",
          ["resource.k8s.io", "v1alpha3", "devicetaintrules"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1alpha3", "resourcepoolstatusrequests"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta1", "deviceclasses"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta1", "resourceclaims"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta1", "resourceclaimtemplates"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta1", "resourceslices"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta2", "deviceclasses"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta2", "devicetaintrules"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta2", "resourceclaims"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta2", "resourceclaimtemplates"] => "DynamicResourceAllocation",
          ["resource.k8s.io", "v1beta2", "resourceslices"] => "DynamicResourceAllocation",
          ["scheduling.k8s.io", "v1alpha2", "podgroups"] => "GenericWorkload",
          ["scheduling.k8s.io", "v1alpha2", "workloads"] => "GenericWorkload",
          ["storage.k8s.io", "v1beta1", "volumeattributesclasses"] => "VolumeAttributesClass",
          ["storagemigration.k8s.io", "v1beta1", "storageversionmigrations"] => "StorageVersionMigrator"
        }.freeze

        private

        def api_group_response(route)
          group_resources = enabled_resources.select { |resource| resource.group == route.group.to_s }
          if group_resources.empty? && @aggregator&.claims?(route.group.to_s)
            aggregated = @aggregator.groups.find { |group| group["name"] == route.group.to_s }
            return json_response({"apiVersion" => "v1", "kind" => "APIGroup"}.merge(aggregated))
          end
          return discovery_not_found_response if group_resources.empty?

          versions = ordered_group_versions(route.group.to_s, group_resources.map(&:version)).map do |version|
            {"groupVersion" => "#{route.group}/#{version}", "version" => version}
          end
          json_response({
                          "apiVersion" => "v1",
                          "kind" => "APIGroup",
                          "name" => route.group.to_s,
                          "versions" => versions,
                          "preferredVersion" => versions.first
                        })
        end

        def resource_list_response(route)
          resources = enabled_resources.select { |resource| resource.group == route.group.to_s && resource.version == route.version.to_s }
          if resources.empty?
            group_served = enabled_resources.any? { |resource| resource.group == route.group.to_s }
            return discovery_not_found_response unless group_served

            return error_response(
              Status::NotFound.new(
                "the server could not find the requested resource",
                details: {}
              )
            )
          end
          json_response({
                          "apiVersion" => "v1",
                          "groupVersion" => route.api_version,
                          "kind" => "APIResourceList",
                          "resources" => resources.sort_by(&:resource).flat_map { |resource| resource_discovery_entries(resource) }
                            .sort_by { |entry| entry.fetch("name") }
                        })
        end

        def resource_discovery_entries(resource)
          primary = resource_discovery(resource)
          subresources = resource.subresources.map do |subresource|
            entry = {
              "name" => "#{resource.resource}/#{subresource.resource}",
              "singularName" => "",
              "namespaced" => resource.namespaced?,
              "kind" => subresource.kind || resource.kind,
              "verbs" => subresource.verbs
            }
            # APIResourceList records the response identity for cross-group
            # subresources.  Omitting these fields makes clients lose the
            # autoscaling/v1 Scale aliases even though the parent route exists.
            advertised_group = subresource.advertised_group(resource.group)
            advertised_version = subresource.advertised_version(resource.group, resource.version)
            entry["group"] = advertised_group if advertised_group
            entry["version"] = advertised_version if advertised_version
            entry
          end
          [primary, *subresources]
        end

        def resource_discovery(resource)
          {
            "name" => resource.resource,
            "singularName" => resource.singular_name,
            "namespaced" => resource.namespaced?,
            "kind" => resource.kind,
            "verbs" => resource.verbs,
            "shortNames" => resource.short_names,
            "categories" => resource.categories
          }.tap do |payload|
            payload["storageVersionHash"] = resource.storage_version_hash if resource.storage_version_hash && feature_gate_enabled?("StorageVersionHash")
          end
        end

        def version_payload
          {"major" => @version_info.fetch("major"), "minor" => @version_info.fetch("minor"),
           "gitVersion" => @version_info.fetch("gitVersion"), "gitCommit" => @version_info.fetch("gitCommit"),
           "gitTreeState" => @version_info.fetch("gitTreeState"), "buildDate" => @version_info.fetch("buildDate"),
           "goVersion" => @version_info.fetch("goVersion"), "compiler" => @version_info.fetch("compiler"),
           "platform" => @version_info.fetch("platform")}
        end

        def api_versions_payload
          versions = enabled_resources.select { |resource| resource.group.empty? }.map(&:version).uniq.sort
          {"kind" => "APIVersions", "apiVersion" => "v1", "versions" => versions,
           "serverAddressByClientCIDRs" => []}
        end

        # apidiscovery.k8s.io/v2: kubectl 1.31+ asks /api and /apis for the
        # whole resource surface in a single round trip instead of one request
        # per group version.  The request is recognised by the Accept header's
        # `as=APIGroupDiscoveryList` conversion, and a client that does not ask
        # for it still gets the classic APIGroupList.
        AGGREGATED_DISCOVERY_GROUP = "apidiscovery.k8s.io"

        AGGREGATED_DISCOVERY_VERSION = "v2"

        AGGREGATED_DISCOVERY_KIND = "APIGroupDiscoveryList"

        def discovery_response(request, core_only:)
          clause = Negotiation.parse_accept(request.header("accept")).find do |candidate|
            candidate.quality.positive? && Negotiation::STANDARD_TYPES.any? { |media_type| candidate.matches?(media_type) } &&
              (candidate.params["as"].nil? || aggregated_discovery_clause?(candidate))
          end
          unless clause && aggregated_discovery_clause?(clause)
            return json_response(core_only ? api_versions_payload : api_groups_payload)
          end

          no_peer = clause.params["profile"] == "nopeer"
          @metrics&.increment("aggregator_discovery_nopeer_requests_total") if no_peer && feature_gate_enabled?("UnknownVersionInteroperabilityProxy")
          media_type = Negotiation::STANDARD_TYPES.find { |type| clause.matches?(type) }
          aggregated_discovery_response(request, core_only: core_only, include_peers: !no_peer, media_type: media_type)
        end

        def aggregated_discovery_clause?(clause)
          params = clause.params
          params["as"] == AGGREGATED_DISCOVERY_KIND && params["g"] == AGGREGATED_DISCOVERY_GROUP &&
            params["v"] == AGGREGATED_DISCOVERY_VERSION
        end

        def aggregated_discovery_response(request, core_only:, include_peers:, media_type:)
          selected = enabled_resources.select { |resource| core_only ? resource.group.empty? : !resource.group.empty? }
          items = selected.group_by(&:group).sort_by { |group, _| group }.map do |group, resources|
            versions = ordered_group_versions(group, resources.map(&:version)).map do |version|
              entries = resources.select { |resource| resource.version == version }.sort_by(&:resource)
              {"version" => version,
               "resources" => entries.map { |resource| aggregated_discovery_resource(resource) },
               "freshness" => "Current"}
            end
            {"metadata" => {"name" => group, "creationTimestamp" => nil}, "versions" => versions}
          end
          # The response must announce the aggregated representation in its own
          # Content-Type.  client-go decides how to parse a discovery document
          # from that header alone: served as plain application/json the body
          # is read as a legacy APIGroupList, yielding a client that believes
          # the server has no resources at all.
          # Aggregated APIService groups (wardle.example.com/...) live behind a
          # backend, not in enabled_resources, so they must be appended here or
          # the v2 discovery the 1.36 dynamic client reads omits them entirely.
          items += @aggregator.discovery_items if !core_only && @aggregator
          items = @peer_proxy.aggregate(items) if !core_only && include_peers && @peer_proxy
          body = {"kind" => AGGREGATED_DISCOVERY_KIND,
                  "apiVersion" => "#{AGGREGATED_DISCOVERY_GROUP}/#{AGGREGATED_DISCOVERY_VERSION}",
                  "metadata" => {}, "items" => items}
          content_type = "#{media_type};g=#{AGGREGATED_DISCOVERY_GROUP};v=#{AGGREGATED_DISCOVERY_VERSION};as=#{AGGREGATED_DISCOVERY_KIND}"
          etag = %("#{Digest::SHA512.hexdigest(JSON.generate(body)).upcase}")
          headers = {"content-type" => content_type, "cache-control" => "public", "vary" => "Accept", "etag" => etag}
          return Response.new(status: 304, headers: headers.except("content-type")) if request.header("if-none-match") == etag

          encoded = case media_type
                    when Negotiation::PROTOBUF_TYPE then protobuf_codec.encode(body)
                    when Negotiation::YAML_TYPE then Negotiation.dump_yaml(body)
                    end
          Response.new(status: 200, headers: headers, body: body, encoded_body: encoded)
        end

        def aggregated_discovery_resource(resource)
          entry = {
            "resource" => resource.resource,
            "responseKind" => {"group" => resource.group, "version" => resource.version, "kind" => resource.kind},
            "scope" => resource.namespaced? ? "Namespaced" : "Cluster",
            "singularResource" => resource.singular_name.to_s,
            "verbs" => resource.verbs
          }
          short_names = Array(resource.short_names)
          entry["shortNames"] = short_names unless short_names.empty?
          categories = Array(resource.categories)
          entry["categories"] = categories unless categories.empty?
          subresources = resource.subresources.map do |subresource|
            {"subresource" => subresource.resource,
             "responseKind" => {"group" => subresource.advertised_group(resource.group).to_s,
                                "version" => subresource.advertised_version(resource.group, resource.version).to_s,
                                "kind" => subresource.kind || resource.kind},
             "verbs" => subresource.verbs}
          end
          entry["subresources"] = subresources unless subresources.empty?
          entry
        end

        def api_groups_payload
          groups = enabled_resources.reject { |resource| resource.group.empty? }.group_by(&:group).sort.map do |group, resources|
            versions = ordered_group_versions(group, resources.map(&:version)).map do |version|
              {"groupVersion" => "#{group}/#{version}", "version" => version}
            end
            {"name" => group, "versions" => versions, "preferredVersion" => versions.first}
          end
          if @aggregator
            @aggregator.groups.each do |aggregated|
              existing = groups.find { |group| group["name"] == aggregated["name"] }
              if existing
                aggregated["versions"].each { |version| existing["versions"] << version unless existing["versions"].include?(version) }
              else
                groups << aggregated
              end
            end
            groups.sort_by! { |group| group["name"] }
          end
          {"kind" => "APIGroupList", "apiVersion" => "v1", "groups" => groups}
        end

        def ordered_group_versions(group, versions)
          available = versions.map(&:to_s).uniq
          pinned = PINNED_VERSION_PRIORITY.fetch(group.to_s, [])
          ordered = pinned.select { |version| available.include?(version) }
          ordered + (available - ordered).sort { |left, right| compare_kube_aware_versions(right, left) }
        end

        # apimachinery version.CompareKubeAwareVersionStrings: GA before beta
        # before alpha, higher major first, then higher minor; unparseable
        # versions sort after parseable ones, among themselves reverse-lexically.
        KUBE_VERSION_PATTERN = /\Av(\d+)(?:(alpha|beta)(\d+))?\z/

        KUBE_VERSION_TYPES = {"alpha" => 0, "beta" => 1, nil => 2}.freeze

        def compare_kube_aware_versions(left, right)
          return 0 if left == right

          left_match = KUBE_VERSION_PATTERN.match(left)
          right_match = KUBE_VERSION_PATTERN.match(right)
          return right <=> left if left_match.nil? && right_match.nil?
          return -1 if left_match.nil?
          return 1 if right_match.nil?

          left_type = KUBE_VERSION_TYPES.fetch(left_match[2])
          right_type = KUBE_VERSION_TYPES.fetch(right_match[2])
          return left_type <=> right_type if left_type != right_type
          return left_match[1].to_i <=> right_match[1].to_i if left_match[1].to_i != right_match[1].to_i

          left_match[3].to_i <=> right_match[3].to_i
        end

        def enabled_resources
          @registry.resources.select { |resource| resource_enabled?(resource) }
        end

        # Group/versions served by the pinned kube-apiserver under its default
        # flags (schema/kubernetes/v1.36.2-defaults/bootstrap/discovery-default.json).
        DEFAULT_SERVED_GROUP_VERSIONS = begin
          path = File.expand_path("../../../../schema/kubernetes/v1.36.2-defaults/bootstrap/discovery-default.json", __dir__)
          if File.file?(path)
            JSON.parse(File.read(path)).keys.filter_map do |key|
              next "v1" if key == "/api/v1"
              next unless key.start_with?("/apis/") && key.count("/") == 3

              key.delete_prefix("/apis/")
            end.to_set
          end
        end

        def version_served?(resource)
          return true if resource.custom?
          return true if DEFAULT_SERVED_GROUP_VERSIONS.nil?

          group_version = resource.group.empty? ? resource.version : "#{resource.group}/#{resource.version}"
          value = @runtime_config[group_version]
          return [true, "true"].include?(value) unless value.nil?
          return true if %w[true 1].include?(@runtime_config["api/all"].to_s)

          DEFAULT_SERVED_GROUP_VERSIONS.include?(group_version)
        end

        # Feature-gate defaults from the pinned corpus
        # (schema/kubernetes/v1.36.2-defaults/features.json); the hand-written
        # DEFAULT_FEATURE_GATES table is the fallback when the corpus is absent.
        CORPUS_FEATURE_GATES = begin
          path = File.expand_path("../../../../schema/kubernetes/v1.36.2-defaults/features.json", __dir__)
          File.file?(path) ? JSON.parse(File.read(path)).fetch("gates").transform_values { |gate| gate["default"] == true } : nil
        end

        def feature_gate_enabled?(gate)
          return @feature_gates.fetch(gate) == true if @feature_gates&.key?(gate)
          return CORPUS_FEATURE_GATES.fetch(gate, false) == true if CORPUS_FEATURE_GATES

          DEFAULT_FEATURE_GATES.fetch(gate, false) == true
        end

        # A resource is served when its group/version is enabled by the runtime
        # configuration and the feature gate guarding the resource (if any) is
        # on, exactly as kube-apiserver's resource config composes them.
        def resource_enabled?(resource)
          return false unless version_served?(resource)

          gate = DEFAULT_DISABLED_GATES_BY_GVR[[resource.group, resource.version, resource.resource]]
          return true unless gate

          feature_gate_enabled?(gate)
        end

        # kube-apiserver routes an unserved discovery group/version through the
        # generic HTTP not-found handler rather than the Kubernetes Status
        # serializer. Clients observe this exact plain-text body and the
        # nosniff/content headers, including for APIs disabled by feature gates.
        def discovery_not_found_response
          Response.new(
            status: 404,
            headers: {
              "cache-control" => "no-cache, private",
              "content-type" => "text/plain; charset=utf-8",
              "x-content-type-options" => "nosniff"
            },
            body: "404 page not found\n"
          )
        end
      end
    end
  end
end
