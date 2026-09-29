# frozen_string_literal: true

# Test/evidence-only adapter for the pinned Kubernetes generated protobuf
# implementations.  It generates a small Go program with static imports for
# the exact descriptor inventory, then executes it against the verified
# v1.36.2 source checkout.  No Go dependency is introduced into lib/ or the
# packaged gem.

require "base64"
require "digest"
require "json"
require "open3"
require "tmpdir"

require_relative "m1_gate"

module M1KubernetesProtobufOracle
  KUBERNETES_VERSION = "v1.36.2"
  SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  MODULES = %w[
    k8s.io/api
    k8s.io/apimachinery
    k8s.io/apiextensions-apiserver
    k8s.io/kube-aggregator
    k8s.io/streaming
  ].freeze
  MODULE_SOURCE_PATHS = MODULES.to_h do |name|
    [name, "staging/src/#{name}"]
  end.freeze

  class OracleError < StandardError; end

  module_function

  def compare(source_root:, registry:, requests:, go: ENV.fetch("GO", "go"))
    source_root = ::File.expand_path(source_root)
    verify_source!(source_root)
    normalized_requests = normalize_requests(requests)
    raise OracleError, "Kubernetes protobuf oracle request inventory is empty" if normalized_requests.empty?

    source, mapping = go_source(registry, normalized_requests)
    response, go_version = execute_go(
      go: go,
      source_root: source_root,
      source: source,
      requests: normalized_requests
    )
    expected_ids = normalized_requests.map { |entry| entry.fetch("id") }.sort
    actual_ids = response.map { |entry| entry.fetch("id") }.sort
    unless actual_ids == expected_ids && actual_ids.uniq.length == actual_ids.length
      raise OracleError, "Kubernetes protobuf oracle response inventory does not match requests"
    end

    runner_sha256 = Digest::SHA256.hexdigest(source)
    request_seed_sha256 = Digest::SHA256.hexdigest(JSON.generate(normalized_requests))
    provenance = {
      "kind" => M1Gate::KUBERNETES_PROTOBUF_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "pinned generated.pb.go Marshal/Unmarshal plus runtime.Unknown",
      "source" => {
        "version" => KUBERNETES_VERSION,
        "commit" => SOURCE_COMMIT,
        "tag" => KUBERNETES_VERSION,
        "root" => source_root,
        "tree_clean" => true
      },
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request_seed_sha256
    }
    provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)

    {
      "executed" => true,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => SOURCE_COMMIT,
      "source_tag" => KUBERNETES_VERSION,
      "source_root" => source_root,
      "source_tree_clean" => true,
      "go_version" => go_version,
      "helper_sha256" => Digest::SHA256.hexdigest(source),
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request_seed_sha256,
      "mapping_sha256" => Digest::SHA256.hexdigest(JSON.generate(mapping.sort.to_h)),
      "comparison_count" => response.length,
      "missing_comparison_count" => 0,
      "implementation" => "pinned generated.pb.go Marshal/Unmarshal plus runtime.Unknown",
      "unknown_concrete_behavior" => "discard",
      "unknown_envelope_behavior" => "preserve_raw",
      "defaulting_observable" => "generated zero-value Marshal bytes",
      "validation_observable" => "generated Unmarshal rejection of truncated length-delimited wire",
      "semantic_defaulting_scope" => "not claimed; descriptor-wide cases use the upstream generated zero-value serializer observable",
      "compatibility_ceiling" => "exact upstream bytes are checked after generated custom-type normalization; generic Hash encoding is descriptor-wire compatible but not claimed to reproduce every gogoproto custom marshaler",
      "provenance" => provenance,
      "results" => response.sort_by { |entry| entry.fetch("id") }
    }
  end

  def verify_source!(source_root)
    unless ::File.directory?(::File.join(source_root, ".git"))
      raise OracleError, "Kubernetes oracle source is not a Git checkout: #{source_root}"
    end
    commit = capture!("git", "-C", source_root, "rev-parse", "HEAD").strip
    unless commit == SOURCE_COMMIT
      raise OracleError, "Kubernetes oracle source commit must be #{SOURCE_COMMIT}, got #{commit}"
    end
    tag = capture!("git", "-C", source_root, "describe", "--tags", "--exact-match", "HEAD").strip
    unless tag == KUBERNETES_VERSION
      raise OracleError, "Kubernetes oracle source tag must be #{KUBERNETES_VERSION}, got #{tag.inspect}"
    end
    dirty = capture!("git", "-C", source_root, "status", "--porcelain", "--untracked-files=no").strip
    raise OracleError, "Kubernetes oracle source checkout has tracked modifications" unless dirty.empty?

    MODULE_SOURCE_PATHS.each_value do |relative|
      module_root = ::File.join(source_root, relative)
      unless ::File.file?(::File.join(module_root, "go.mod"))
        raise OracleError, "Kubernetes oracle source module is unavailable: #{relative}"
      end
    end
  end

  def normalize_requests(requests)
    seen = {}
    Array(requests).map do |request|
      entry = request.transform_keys(&:to_s)
      id = String(entry.fetch("id"))
      descriptor = String(entry.fetch("descriptor"))
      raise OracleError, "duplicate Kubernetes oracle request #{id.inspect}" if seen.key?(id)

      seen[id] = true
      %w[raw raw_with_unknown envelope_with_unknown].each do |key|
        value = entry.fetch(key)
        unless value.is_a?(String) && Base64.strict_encode64(Base64.strict_decode64(value)) == value
          raise OracleError, "oracle request #{id.inspect} #{key} must be canonical base64"
        end
      rescue ArgumentError
        raise OracleError, "oracle request #{id.inspect} #{key} must be canonical base64"
      end
      {
        "id" => id,
        "descriptor" => descriptor,
        "raw" => entry.fetch("raw"),
        "raw_with_unknown" => entry.fetch("raw_with_unknown"),
        "envelope_with_unknown" => entry.fetch("envelope_with_unknown")
      }.freeze
    end.sort_by { |entry| entry.fetch("id") }.freeze
  end

  def go_source(registry, requests)
    files_by_package = registry.files.each_with_object({}) { |file, index| index[file.package] = file }
    mappings = requests.each_with_object({}) do |request, result|
      descriptor = registry.fetch(request.fetch("descriptor"))
      file = files_by_package.fetch(descriptor.package) do
        raise OracleError, "no generated.proto file owns #{descriptor.full_name}"
      end
      go_package = file.options["go_package"]
      unless go_package.is_a?(String) && !go_package.empty?
        raise OracleError, "generated.proto for #{descriptor.full_name} has no go_package"
      end
      unless descriptor.name.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)
        raise OracleError, "protobuf message name is not a Go identifier: #{descriptor.name.inspect}"
      end
      result[request.fetch("id")] = [go_package, descriptor.name]
    end

    runtime_package = "k8s.io/apimachinery/pkg/runtime"
    imports = (mappings.values.map(&:first) + [runtime_package]).uniq.sort
    aliases = imports.each_with_index.to_h { |path, index| [path, "oraclepkg#{index}"] }
    import_source = imports.map { |path| "\t#{aliases.fetch(path)} #{JSON.generate(path)}" }.join("\n")
    switch_source = mappings.sort.map do |id, (go_package, type_name)|
      "\tcase #{JSON.generate(id)}:\n\t\treturn &#{aliases.fetch(go_package)}.#{type_name}{}, nil"
    end.join("\n")
    runtime_alias = aliases.fetch(runtime_package)

    source = <<~GO
      package main

      import (
      	"bytes"
      	"encoding/base64"
      	"encoding/json"
      	"fmt"
      	"os"
      	"reflect"
      	"runtime"

      #{import_source}
      )

      var kubernetesMagic = []byte{'k', '8', 's', 0}

      type wireMessage interface {
      	Marshal() ([]byte, error)
      	Unmarshal([]byte) error
      }

      type request struct {
      	ID                  string `json:"id"`
      	Raw                 string `json:"raw"`
      	RawWithUnknown      string `json:"raw_with_unknown"`
      	EnvelopeWithUnknown string `json:"envelope_with_unknown"`
      }

      type result struct {
      	ID                    string `json:"id"`
       GoType                string `json:"go_type"`
       KnownRemarshal        string `json:"known_remarshal"`
       KnownSecondRemarshal  string `json:"known_second_remarshal"`
       ZeroMarshal           string `json:"zero_marshal"`
      	UnknownRemarshal      string `json:"unknown_remarshal"`
      	EnvelopeRemarshal     string `json:"envelope_remarshal"`
      	EnvelopeRaw           string `json:"envelope_raw"`
      	MalformedWireRejected bool   `json:"malformed_wire_rejected"`
      	Error                 string `json:"error,omitempty"`
      }

      type response struct {
      	GoVersion string   `json:"go_version"`
      	Results   []result `json:"results"`
      }

      func newMessage(id string) (wireMessage, error) {
      	switch id {
      #{switch_source}
      	default:
      		return nil, fmt.Errorf("unmapped schema %q", id)
      	}
      }

      func decode(value string) ([]byte, error) {
      	return base64.StdEncoding.Strict().DecodeString(value)
      }

      func encode(value []byte) string {
      	return base64.StdEncoding.EncodeToString(value)
      }

      func compareOne(input request) (output result) {
      	output.ID = input.ID
      	message, err := newMessage(input.ID)
      	if err != nil {
      		output.Error = err.Error()
      		return
      	}
      	output.GoType = reflect.TypeOf(message).String()
      	raw, err := decode(input.Raw)
      	if err != nil {
      		output.Error = "raw base64: " + err.Error()
      		return
      	}
      	if err := message.Unmarshal(raw); err != nil {
      		output.Error = "known unmarshal: " + err.Error()
      		return
      	}
      	known, err := message.Marshal()
      	if err != nil {
      		output.Error = "known marshal: " + err.Error()
      		return
      	}
       output.KnownRemarshal = encode(known)

	      canonical, err := newMessage(input.ID)
	      if err != nil {
	       output.Error = err.Error()
	       return
	      }
	      if err := canonical.Unmarshal(known); err != nil {
	       output.Error = "canonical unmarshal: " + err.Error()
	       return
	      }
	      secondKnown, err := canonical.Marshal()
	      if err != nil {
	       output.Error = "canonical marshal: " + err.Error()
	       return
	      }
	      output.KnownSecondRemarshal = encode(secondKnown)

      	zero, err := newMessage(input.ID)
      	if err != nil {
      		output.Error = err.Error()
      		return
      	}
      	zeroBytes, err := zero.Marshal()
      	if err != nil {
      		output.Error = "zero marshal: " + err.Error()
      		return
      	}
      	output.ZeroMarshal = encode(zeroBytes)

      	rawUnknown, err := decode(input.RawWithUnknown)
      	if err != nil {
      		output.Error = "unknown raw base64: " + err.Error()
      		return
      	}
      	unknown, err := newMessage(input.ID)
      	if err != nil {
      		output.Error = err.Error()
      		return
      	}
      	if err := unknown.Unmarshal(rawUnknown); err != nil {
      		output.Error = "unknown unmarshal: " + err.Error()
      		return
      	}
      	unknownBytes, err := unknown.Marshal()
      	if err != nil {
      		output.Error = "unknown marshal: " + err.Error()
      		return
      	}
      	output.UnknownRemarshal = encode(unknownBytes)

      	envelope, err := decode(input.EnvelopeWithUnknown)
      	if err != nil {
      		output.Error = "envelope base64: " + err.Error()
      		return
      	}
      	if len(envelope) < len(kubernetesMagic) || !bytes.Equal(envelope[:len(kubernetesMagic)], kubernetesMagic) {
      		output.Error = "envelope has no k8s\\x00 magic"
      		return
      	}
      	var runtimeUnknown #{runtime_alias}.Unknown
      	if err := runtimeUnknown.Unmarshal(envelope[len(kubernetesMagic):]); err != nil {
      		output.Error = "runtime.Unknown unmarshal: " + err.Error()
      		return
      	}
      	output.EnvelopeRaw = encode(runtimeUnknown.Raw)
      	runtimeBytes, err := runtimeUnknown.Marshal()
      	if err != nil {
      		output.Error = "runtime.Unknown marshal: " + err.Error()
      		return
      	}
      	output.EnvelopeRemarshal = encode(append(append([]byte{}, kubernetesMagic...), runtimeBytes...))

      	malformed, err := newMessage(input.ID)
      	if err != nil {
      		output.Error = err.Error()
      		return
      	}
      	output.MalformedWireRejected = malformed.Unmarshal([]byte{0x0a, 0x80}) != nil
      	return
      }

      func main() {
      	var input []request
      	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
      		fmt.Fprintln(os.Stderr, "input:", err)
      		os.Exit(2)
      	}
      	results := make([]result, 0, len(input))
      	for _, item := range input {
      		results = append(results, compareOne(item))
      	}
      	encoder := json.NewEncoder(os.Stdout)
      	encoder.SetEscapeHTML(false)
      	if err := encoder.Encode(response{GoVersion: runtime.Version(), Results: results}); err != nil {
      		fmt.Fprintln(os.Stderr, "output:", err)
      		os.Exit(3)
      	}
      }
    GO
    [source, mappings.transform_values { |go_package, type_name| "#{go_package}.#{type_name}" }.freeze]
  end

  def execute_go(go:, source_root:, source:, requests:)
    Dir.mktmpdir("rubernetes-kubernetes-protobuf-oracle-") do |directory|
      ::File.write(::File.join(directory, "main.go"), source)
      ::File.write(::File.join(directory, "go.mod"), go_mod(source_root))
      _tidy_stdout, tidy_stderr, tidy_status = Open3.capture3(
        {"GOWORK" => "off", "CGO_ENABLED" => "0"},
        go, "mod", "tidy",
        chdir: directory
      )
      unless tidy_status.success?
        detail = tidy_stderr.lines.last(20).join.strip
        raise OracleError, "Kubernetes protobuf oracle dependency resolution failed (#{tidy_status.exitstatus}): #{detail}"
      end
      stdout, stderr, status = Open3.capture3(
        {"GOWORK" => "off", "CGO_ENABLED" => "0"},
        go, "run", ".",
        stdin_data: JSON.generate(requests),
        chdir: directory
      )
      unless status.success?
        detail = stderr.lines.last(20).join.strip
        raise OracleError, "Kubernetes protobuf oracle Go helper failed (#{status.exitstatus}): #{detail}"
      end
      document = JSON.parse(stdout, max_nesting: 64)
      results = document.fetch("results")
      raise OracleError, "Kubernetes protobuf oracle results must be an array" unless results.is_a?(Array)

      [results, String(document.fetch("go_version"))]
    end
  rescue JSON::ParserError => error
    raise OracleError, "Kubernetes protobuf oracle returned invalid JSON: #{error.message}"
  end

  def go_mod(source_root)
    requirements = MODULES.map { |name| "\t#{name} v0.0.0" }.join("\n")
    replacements = MODULE_SOURCE_PATHS.map do |name, relative|
      "\t#{name} => #{::File.join(source_root, relative)}"
    end.join("\n")
    <<~MOD
      module rubernetes.dev/m1-protobuf-oracle

      go 1.26.0

      require (
      #{requirements}
      )

      replace (
      #{replacements}
      )
    MOD
  end

  def capture!(*argv)
    stdout, stderr, status = Open3.capture3(*argv)
    return stdout if status.success?

    raise OracleError, "command failed: #{argv.join(" ")}: #{stderr.strip}"
  rescue SystemCallError => error
    raise OracleError, "command could not execute: #{argv.first}: #{error.message}"
  end
end
