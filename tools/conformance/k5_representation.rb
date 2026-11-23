# frozen_string_literal: true

require "json"
require "yaml"

require_relative "../../lib/rubernetes/client"
require_relative "../../lib/rubernetes/schema/codec/kubernetes_cbor"
require_relative "../../lib/rubernetes/schema/codec/kubernetes_protobuf"

module Conformance
  module K5Representation
    PROTOBUF = Rubernetes::Schema::Codec::KubernetesProtobuf
    CBOR = Rubernetes::Schema::Codec::KubernetesCBOR
    CONFIGMAPS = "/api/v1/namespaces/default/configmaps"
    DATA = {"a" => "b", "c" => "d"}.freeze
    JSON_TYPE = "application/json"
    YAML_TYPE = "application/yaml"

    module_function

    # Run after the K5 fixture's merge patch and before it is deleted.
    def observables(cbor_enabled: false)
      cbor_type = cbor_enabled ? CBOR::CONTENT_TYPE : JSON_TYPE
      [
        observable("yaml_configmap", YAML_TYPE),
        observable("protobuf_configmap", PROTOBUF::CONTENT_TYPE),
        observable("preferred_protobuf_configmap", "#{YAML_TYPE};q=0.2, #{PROTOBUF::CONTENT_TYPE};q=0.9", type: PROTOBUF::CONTENT_TYPE),
        observable("cbor_configmap", CBOR::CONTENT_TYPE, type: cbor_type, status: cbor_enabled ? 200 : 406),
        observable("cbor_configmap_fallback", "#{CBOR::CONTENT_TYPE}, #{JSON_TYPE};q=0.9", type: cbor_type),
        observable("unsupported_configmap_accept", "application/x-k5-unsupported", type: JSON_TYPE, status: 406),
        observable("malformed_configmap_accept", "not-a-media-type", type: JSON_TYPE, status: 406)
      ]
    end

    def probe(observable, kubeconfig, fixture)
      context = Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve
      client = Rubernetes::Client::HTTPClient.new(context: context, read_timeout: 15)
      response = client.request("GET", "#{CONFIGMAPS}/#{fixture}", headers: {"Accept" => observable.fetch("representation")})
      content_type = response["content-type"].to_s
      body = decode(content_type.split(";", 2).first, response.body)
      expected = response.status == observable.fetch("http_status") && content_type == observable.fetch("content_type") &&
                 expected_body?(body, fixture, response.status)
      {"exit_status" => expected ? 0 : 1, "stdout" => JSON.generate(body), "stderr" => "",
       "http_status" => response.status, "content_type" => content_type}
    rescue Rubernetes::Client::Error, Rubernetes::Schema::Codec::Error, JSON::ParserError, Psych::Exception, ArgumentError => error
      {"exit_status" => 1, "stdout" => "", "stderr" => "#{error.class}: #{error.message}",
       "http_status" => response&.status, "content_type" => content_type}
    ensure
      client&.close
    end

    def observable(id, accept, type: accept, status: 200)
      {"id" => id, "representation" => accept, "http_status" => status, "content_type" => type}
    end

    def decode(type, bytes)
      case type
      when JSON_TYPE then JSON.parse(bytes)
      when YAML_TYPE then YAML.safe_load(bytes)
      when PROTOBUF::CONTENT_TYPE then PROTOBUF.new.decode(bytes)
      when CBOR::CONTENT_TYPE
        raise ArgumentError, "Kubernetes CBOR object is missing its self-described format tag" unless bytes.b.start_with?(CBOR::PREFIX)

        CBOR.decode(bytes)
      else raise ArgumentError, "unexpected Content-Type #{type.inspect}"
      end
    end

    def expected_body?(body, fixture, status)
      return false unless body.is_a?(Hash)
      return expected_status?(body) if status == 406

      body.values_at("apiVersion", "kind", "data") == ["v1", "ConfigMap", DATA] &&
        body.dig("metadata", "namespace") == "default" && body.dig("metadata", "name") == fixture
    end

    def expected_status?(body)
      body.values_at("apiVersion", "kind", "status", "reason", "code") == ["v1", "Status", "Failure", "NotAcceptable", 406]
    end
  end
end
