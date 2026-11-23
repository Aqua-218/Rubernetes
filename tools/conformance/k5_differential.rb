#!/usr/bin/env ruby
# frozen_string_literal: true

# K5 — API and wire differential (spec/verification/kubernetes-compatibility.md#k5).
#
# Drives the same request sequence from one seed against the Rubernetes cluster
# and the pinned Kubernetes v1.36.2 oracle, then compares the normalised
# observables.  Values that are legitimately per-cluster (UID, timestamp,
# random suffix, node address) are compared on format, uniqueness, monotonicity
# and causal order rather than equality, as the spec requires.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "securerandom"
require "time"

require_relative "../../lib/rubernetes/client"
require_relative "../../lib/rubernetes/schema/codec"
require_relative "../../lib/rubernetes/schema/codec/kubernetes_protobuf"
require_relative "lock"
require_relative "k5_config_map_watch"
require_relative "k5_list_watch"
require_relative "k5_representation"
require_relative "k5_apply_ownership"

module Conformance
  module K5Differential
    ROOT = File.expand_path("../..", __dir__)
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")

    PROTOBUF = Rubernetes::Schema::Codec::KubernetesProtobuf
    PODS = "/api/v1/namespaces/default/pods"
    SERVICE_ACCOUNTS = "/api/v1/namespaces/default/serviceaccounts"
    PRIORITY_CLASSES = "/apis/scheduling.k8s.io/v1/priorityclasses"

    STDIN_BODIES = {
      "apply_configmap_conflict" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                                     "metadata" => {"name" => "k5-cm", "namespace" => "default"},
                                     "data" => {"a" => "conflicting-write"}},
      "unknown_field_strict" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                                 "metadata" => {"name" => "k5-strict", "namespace" => "default"},
                                 "dataz" => {"a" => "b"}},
      "invalid_object" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                           "metadata" => {"name" => "K5 Invalid Name"}, "data" => {"a" => "b"}}
    }.freeze

    # Fields whose value is per-cluster; compared structurally, not literally.
    VOLATILE = %w[uid resourceVersion creationTimestamp generation
                  time lastTransitionTime lastUpdateTime
                  selfLink resourceVersionMatch startTime podIP hostIP nodeName
                  clusterIP clusterIPs bootID machineID systemUUID kubeletVersion
                  kubeProxyVersion containerRuntimeVersion osImage kernelVersion].freeze

    module_function

    # Observable groups from the spec, each a sequence of kubectl invocations
    # whose normalised output must agree between the two clusters.
    def observables(cbor_enabled:)
      [
        {"id" => "discovery_groups", "argv" => %w[api-versions]},
        {"id" => "discovery_resources", "argv" => %w[api-resources --no-headers]},
        {"id" => "openapi_v3_root", "argv" => %w[get --raw /openapi/v3]},
        {"id" => "explain_pod", "argv" => %w[explain pod --recursive]},
        {"id" => "explain_deployment", "argv" => %w[explain deployment.spec]},
        {"id" => "namespace_list", "argv" => %w[get namespaces -o json]},
        {"id" => "create_configmap", "argv" => %w[create configmap k5-cm --field-manager=k5-create --from-literal=a=b -o json]},
        {"id" => "get_configmap", "argv" => %w[get configmap k5-cm -o json]},
        {"id" => "patch_configmap", "argv" => ["patch", "configmap", "k5-cm", "--type=merge", "-p", '{"data":{"c":"d"}}', "-o", "json"]},
        *K5Representation.observables(cbor_enabled: cbor_enabled),
        {"id" => "apply_configmap_conflict", "argv" => %w[apply -f - --server-side --field-manager=k5-apply -o json],
         "stdin" => true, "expected_error" => /conflict.*\.data\.a/im},
        {"id" => "configmap_apply_ownership_transfer"},
        {"id" => "unknown_field_strict", "argv" => %w[create --raw /api/v1/namespaces/default/configmaps?fieldValidation=Strict&dryRun=All -f -],
         "stdin" => true, "expected_error" => /strict decoding error.*unknown field.*dataz/i},
        {"id" => "delete_configmap", "argv" => %w[delete configmap k5-cm -o name]},
        {"id" => "missing_object", "argv" => %w[get configmap k5-cm -o json], "expected_error" => /NotFound/},
        {"id" => "invalid_object", "argv" => %w[create -f - -o json], "stdin" => true, "expected_error" => /metadata\.name: Invalid value/},
        {"id" => "auth_can_i", "argv" => %w[auth can-i create pods]},
        {"id" => "protobuf_pod_list", "wire" => true},
        {"id" => "configmap_watch_lifetime"},
        *K5ListWatch.observables,
        {"id" => "priority_class_maximum", "priority_class" => {"value" => 1_000_000_000}, "http_status" => 201},
        {"id" => "priority_class_above_maximum", "priority_class" => {"value" => 1_000_000_001}, "http_status" => 422},
        {"id" => "priority_class_invalid_policy", "priority_class" => {"value" => 0, "preemptionPolicy" => "Other"}, "http_status" => 422},
        {"id" => "priority_class_dry_run_readback", "priority_class" => nil, "http_status" => 404}
      ]
    end

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k5")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--oracle-kubeconfig PATH") { |v| options[:oracle] = v }
        parser.on("--cbor-enabled", "Both clusters enable CBORServingAndStorage") { options[:cbor_enabled] = true }
        parser.on("--output PATH") { |v| options[:output] = v }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?
      raise ArgumentError, "--oracle-kubeconfig is required" if options[:oracle].nil?

      attestation = verify_oracle(options)
      FileUtils.mkdir_p(options[:output])
      options[:fixture] = "k5-#{SecureRandom.hex(8)}"
      results = observables(cbor_enabled: options.fetch(:cbor_enabled, false)).map { |observable| compare(observable, options) }
      differences = results.reject { |entry| entry.fetch("matches") }
      report = {
        "schema_version" => 1,
        "kind" => "k5_api_wire_differential",
        "generated_at" => Time.now.utc.iso8601,
        "attestation" => attestation,
        "fixture" => options.fetch(:fixture),
        "observables" => results.length,
        "matching" => results.count { |entry| entry.fetch("matches") },
        "differences" => differences,
        "cases" => results
      }
      File.write(File.join(options[:output], "differential.json"), "#{JSON.pretty_generate(report)}\n")
      differences.empty? ? 0 : 1
    end

    def verify_oracle(options)
      oracle = options.fetch(:oracle)
      commit = api_object(oracle, "/version").fetch("gitCommit", nil)
      raise ArgumentError, "oracle must serve pinned Kubernetes commit #{Lock.source_commit}" unless commit == Lock.source_commit

      identities = [options.fetch(:kubeconfig), oracle].map do |config|
        api_object(config, "/api/v1/namespaces/default").dig("metadata", "uid")
      end
      unless identities.all? { |uid| uid.is_a?(String) && !uid.empty? } && identities.uniq.length == 2
        raise ArgumentError, "target and oracle must expose distinct default namespace UIDs"
      end

      {"oracle_commit" => commit, "target_default_namespace_uid" => identities.first,
       "oracle_default_namespace_uid" => identities.last}
    end

    def api_object(kubeconfig, path)
      out, _err, status = Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, "--request-timeout=15s", "get", "--raw", path)
      raise ArgumentError, "could not read #{path} for oracle verification" unless status.success?

      JSON.parse(out)
    end

    def compare(observable, options)
      fixture = options.fetch(:fixture)
      ours = invoke(observable, options.fetch(:kubeconfig), fixture)
      theirs = invoke(observable, options.fetch(:oracle), fixture)
      expected = [ours, theirs].all? { |result| response_expected?(observable, result) }
      normalized_ours = normalize(ours, custom_groups: custom_groups(options[:kubeconfig]))
      normalized_theirs = normalize(theirs, custom_groups: custom_groups(options[:oracle]))
      matches = expected && normalized_ours == normalized_theirs
      {
        "id" => observable.fetch("id"),
        "matches" => matches,
        "expected_responses" => expected,
        "rubernetes" => normalized_ours,
        "kubernetes" => normalized_theirs,
        "rubernetes_sha256" => Digest::SHA256.hexdigest(Rubernetes::Schema::Codec.canonical_json(normalized_ours)),
        "kubernetes_sha256" => Digest::SHA256.hexdigest(Rubernetes::Schema::Codec.canonical_json(normalized_theirs)),
        **({"traces" => {"rubernetes" => ours["trace"], "kubernetes" => theirs["trace"]}} if !matches && ours["trace"])
      }
    end

    def response_expected?(observable, result)
      status = result.fetch("exit_status")
      pattern = observable["expected_error"]
      return status == 0 unless pattern

      status == 1 && pattern.match?(result.fetch("stderr"))
    end

    def invoke(observable, kubeconfig, fixture)
      return K5ApplyOwnership.run(kubeconfig, fixture) if observable["id"] == "configmap_apply_ownership_transfer"
      return K5Representation.probe(observable, kubeconfig, fixture) if observable.key?("representation")
      return K5ConfigMapWatch.run(kubeconfig, "#{fixture}-watch") if observable["id"] == "configmap_watch_lifetime"
      return K5ListWatch.run(observable.fetch("list_watch"), kubeconfig, fixture) if observable.key?("list_watch")
      return protobuf_pod_list(kubeconfig, fixture) if observable["wire"]
      return priority_class_probe(observable, kubeconfig, fixture) if observable.key?("priority_class")

      arguments = observable.fetch("argv").map { |value| value == "k5-cm" ? fixture : value }
      argv = [KUBECTL, "--kubeconfig", kubeconfig, "--namespace=default", "--request-timeout=15s", *arguments]
      stdin = stdin_body(observable, fixture)
      stdout, stderr, status = Open3.capture3(*argv, stdin_data: stdin.to_s)
      {"exit_status" => status.exitstatus, "stdout" => stdout, "stderr" => stderr}
    end

    # Compare the complete JSON body (including Status.details.causes), HTTP
    # status and negotiated media type. Read back the same dry-run name.
    def priority_class_probe(observable, kubeconfig, fixture)
      context = Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve
      client = Rubernetes::Client::HTTPClient.new(context: context, read_timeout: 15)
      response = if (fields = observable["priority_class"])
                   object = {"apiVersion" => "scheduling.k8s.io/v1", "kind" => "PriorityClass",
                             "metadata" => {"name" => fixture}}.merge(fields)
                   client.request("POST", PRIORITY_CLASSES, body: object, query: {"dryRun" => "All", "fieldManager" => "k5"})
                 else
                   client.request("GET", "#{PRIORITY_CLASSES}/#{fixture}")
                 end
      type = response["content-type"].to_s.split(";").first
      body = response.json
      expected = response.status == observable.fetch("http_status") && type == "application/json" && body.is_a?(Hash)
      {"exit_status" => expected ? 0 : 1, "stdout" => JSON.generate(body), "stderr" => "",
       "http_status" => response.status, "content_type" => type}
    rescue Rubernetes::Client::Error => error
      wire_failure(error.message)
    ensure
      client&.close
    end

    def stdin_body(observable, fixture)
      return unless observable["stdin"]

      body = STDIN_BODIES.fetch(observable.fetch("id"))
      metadata = body.fetch("metadata")
      body = body.merge("metadata" => metadata.merge("name" => fixture)) if metadata["name"] == "k5-cm"
      JSON.generate(body)
    end

    def protobuf_pod_list(kubeconfig, fixture)
      context = Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve
      client = Rubernetes::Client::HTTPClient.new(context: context, read_timeout: 15)
      account = {"apiVersion" => "v1", "kind" => "ServiceAccount", "metadata" => {"name" => fixture}}
      created = client.request("POST", SERVICE_ACCOUNTS, body: account)
      return wire_failure("ServiceAccount fixture creation returned HTTP #{created.status}") unless created.status == 201

      result = probe_pod_list(client, fixture)
      cleanup_fixture(client, SERVICE_ACCOUNTS, fixture) || result
    rescue Rubernetes::Client::Error => error
      wire_failure(error.message)
    ensure
      client&.close
    end

    def probe_pod_list(client, fixture)
      manifest = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => fixture},
                  "spec" => {"schedulerName" => "k5-wire-probe", "serviceAccountName" => fixture,
                             "automountServiceAccountToken" => false, "containers" => [{"name" => "fixture", "image" => "busybox"}]}}
      created = client.request("POST", PODS, body: manifest)
      return wire_failure("Pod fixture creation returned HTTP #{created.status}") unless created.status == 201

      result = inspect_protobuf_list(client, fixture)
      cleanup_fixture(client, PODS, fixture) || result
    rescue Rubernetes::Client::Error => error
      wire_failure(error.message)
    end

    def cleanup_fixture(client, collection, fixture)
      path = "#{collection}/#{fixture}"
      removed = client.request("DELETE", path, body: {"gracePeriodSeconds" => 0})
      missing = client.request("GET", path)
      return if removed.success? && missing.status == 404

      wire_failure("DELETE #{path} returned HTTP #{removed.status}, readback #{missing.status}")
    end

    def inspect_protobuf_list(client, fixture)
      response = client.request("GET", PODS, headers: {"Accept" => PROTOBUF::CONTENT_TYPE},
                                             query: {"fieldSelector" => "metadata.name=#{fixture}"})
      media_type = response["content-type"].to_s.split(";").first
      unless response.status == 200 && media_type == PROTOBUF::CONTENT_TYPE
        return wire_failure("PodList returned HTTP #{response.status} and #{media_type.inspect}")
      end

      list = PROTOBUF.new.decode(response.body)
      names = Array(list["items"]).map { |pod| pod.dig("metadata", "name") }
      unless list.values_at("apiVersion", "kind") == %w[v1 PodList] && names == [fixture]
        return wire_failure("protobuf PodList did not contain the created fixture")
      end

      {"exit_status" => 0, "stdout" => JSON.generate(list), "stderr" => "",
       "http_status" => response.status, "content_type" => media_type}
    rescue Rubernetes::Client::Error, PROTOBUF::DecodeError, PROTOBUF::UnsupportedKind => error
      wire_failure(error.message)
    end

    def wire_failure(message)
      {"exit_status" => 1, "stdout" => "", "stderr" => message}
    end

    # Structural normalisation: parse JSON when possible, drop per-cluster
    # values but keep whether they were present and well formed, and reduce
    # free text to its stable shape.
    # The API groups a cluster serves from CustomResourceDefinitions.  K5
    # compares the built-in API: a lane that ran after K6 left Argo's CRDs
    # behind, and the oracle has none, so discovery and the OpenAPI root
    # are compared without CRD groups on either side.
    def custom_groups(kubeconfig)
      @custom_groups ||= {}
      @custom_groups[kubeconfig] ||= begin
        out, _err, status = Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, "get", "customresourcedefinitions",
                                           "-o", "jsonpath={range .items[*]}{.spec.group}{\"\\n\"}{end}")
        status.success? ? out.split.uniq.sort : []
      end
    end

    def normalize(result, custom_groups: [])
      body =
        begin
          drop_custom_groups(scrub(JSON.parse(result.fetch("stdout"))), custom_groups)
        rescue JSON::ParserError
          lines = result.fetch("stdout").lines.map(&:strip).reject(&:empty?)
          lines.reject! { |line| custom_groups.any? { |group| line.include?(group) } }
          lines.sort
        end
      {
        "exit_status" => result.fetch("exit_status"),
        "body" => body,
        "error" => scrub_message(result.fetch("stderr")),
        **result.slice("http_status", "content_type")
      }
    end

    # kind, the oracle, adds its own namespaces (local-path-storage); only the
    # namespaces every v1.36.2 cluster has are compared.
    SYSTEM_NAMESPACES = %w[default kube-system kube-public kube-node-lease].freeze

    def scrub(value)
      case value
      when Hash
        items = value["items"]
        generic_namespace_list = value["kind"] == "List" && items.is_a?(Array) &&
                                 items.all? { |item| item.is_a?(Hash) && item["kind"] == "Namespace" }
        if items.is_a?(Array) && (value["kind"] == "NamespaceList" || generic_namespace_list)
          value = value.merge("items" => items.select { |item| SYSTEM_NAMESPACES.include?(item.dig("metadata", "name")) })
        end
        value.each_with_object({}) do |(key, child), out|
          # User keys can have the same spelling as server metadata. FieldsV1
          # is itself a field set whose keys and values must compare exactly.
          out[key] = if %w[data binaryData stringData labels annotations fieldsV1].include?(key)
                       child
                     elsif VOLATILE.include?(key)
                       present_shape(child)
                     elsif key == "serverRelativeURL" && child.is_a?(String)
                       # The OpenAPI document hash is an implementation's own content digest.
                       child.sub(/hash=[0-9A-Fa-f]+/, "hash=<digest>")
                     else
                       scrub(child)
                     end
        end
      when Array then value.map { |child| scrub(child) }
      else value
      end
    end

    def drop_custom_groups(value, groups)
      return value if groups.empty? || !value.is_a?(Hash) || !value["paths"].is_a?(Hash)

      kept = value["paths"].reject { |path, _| groups.any? { |group| path == "apis/#{group}" || path.start_with?("apis/#{group}/") } }
      value.merge("paths" => kept)
    end

    # Keep the observable property of a volatile value: that it exists and what
    # shape it has, never its literal content.
    def present_shape(value)
      case value
      when nil then "<absent>"
      when String
        case value
        when /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/ then "<uuid>"
        when /\A\d{4}-\d{2}-\d{2}T/ then "<rfc3339>"
        when /\A\d+\z/ then "<numeric-string>"
        else "<string>"
        end
      when Integer then "<int>"
      when Array then value.map { |child| present_shape(child) }
      when Hash then "<object:#{value.keys.sort.join(",")}>"
      else "<#{value.class.name.downcase}>"
      end
    end

    def scrub_message(text)
      text.to_s.gsub(/\h{8}-\h{4}-\h{4}-\h{4}-\h{12}/, "<uuid>")
        .gsub(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/, "<rfc3339>")
        .gsub(/\bresourceVersion:?\s*"?\d+"?/, "resourceVersion <n>")
        .lines.map(&:strip).reject(&:empty?).sort
    end
  end
end

exit(Conformance::K5Differential.run) if $PROGRAM_NAME == __FILE__
