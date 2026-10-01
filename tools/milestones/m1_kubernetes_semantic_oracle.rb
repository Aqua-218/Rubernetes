# frozen_string_literal: true

# Test/evidence-only adapter for Kubernetes v1.36.2 JSON, Scheme defaulting,
# and generated declarative validation behavior.  The helper is generated with
# static imports for the exact request inventory and is executed only against
# the verified Kubernetes source checkout.

require "digest"
require "json"
require "open3"
require "tmpdir"

require_relative "m1_gate"

module M1KubernetesSemanticOracle
  KUBERNETES_VERSION = "v1.36.2"
  SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  MODULES = %w[
    k8s.io/api
    k8s.io/apimachinery
    k8s.io/apiextensions-apiserver
    k8s.io/kube-aggregator
    k8s.io/streaming
  ].freeze
  MODULE_SOURCE_PATHS = MODULES.to_h { |name| [name, "staging/src/#{name}"] }.freeze
  RUNTIME_PACKAGE = "k8s.io/apimachinery/pkg/runtime"

  class OracleError < StandardError; end

  module_function

  def compare(source_root:, requests:, go: ENV.fetch("GO", "go"))
    source_root = ::File.expand_path(source_root)
    verify_source!(source_root)
    normalized_requests = normalize_requests(requests)
    raise OracleError, "Kubernetes semantic oracle request inventory is empty" if normalized_requests.empty?

    source, mapping = go_source(source_root, normalized_requests)
    response, go_version = execute_go(
      go: go,
      source_root: source_root,
      source: source,
      requests: normalized_requests
    )
    expected_ids = normalized_requests.map { |entry| entry.fetch("id") }.sort
    actual_ids = response.map { |entry| entry.fetch("id") }.sort
    unless actual_ids == expected_ids && actual_ids.uniq.length == actual_ids.length
      raise OracleError, "Kubernetes semantic oracle response inventory does not match requests"
    end

    runner_sha256 = Digest::SHA256.hexdigest(source)
    request_seed_sha256 = Digest::SHA256.hexdigest(JSON.generate(normalized_requests))
    provenance = {
      "kind" => M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "pinned Go encoding/json plus runtime.Scheme Default and generated validation",
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
    validation_applicable_count = response.count { |entry| entry.fetch("validation").fetch("applicable") == true }
    validation_not_applicable_count = response.length - validation_applicable_count
    validation_criterion = {
      "status" => validation_not_applicable_count.zero? ? "COMPLETE" : "INCOMPLETE",
      "applicable_count" => validation_applicable_count,
      "not_applicable_count" => validation_not_applicable_count,
      "ledger" => response.sort_by { |entry| entry.fetch("id") }.map do |entry|
        validation = entry.fetch("validation")
        {
          "id" => entry.fetch("id"),
          "applicable" => validation.fetch("applicable"),
          "reason" => validation["reason"],
          "source_paths" => Array(validation["source_paths"])
        }
      end
    }

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
      "implementation" => "pinned Go encoding/json plus runtime.Scheme Default and generated validation",
      "json_unknown_behavior" => "encoding/json discards unknown fields in concrete structs; strict decode records field errors",
      "defaulting_observable" => "runtime.Scheme.Default after concrete JSON decode",
      "validation_observable" => "runtime.Scheme.Validate using generated declarative validation registrations",
      "applicability_policy" => "N/A is emitted only for non-runtime objects or types without an upstream validation registration; each reason cites the source package/type",
      "validation_criterion" => validation_criterion,
      "provenance" => provenance,
      "comparisons" => response.sort_by { |entry| entry.fetch("id") }
    }
  end

  def verify_source!(source_root)
    raise OracleError, "Kubernetes oracle source is not a Git checkout: #{source_root}" unless ::File.directory?(::File.join(source_root, ".git"))

    commit = capture!("git", "-C", source_root, "rev-parse", "HEAD").strip
    raise OracleError, "Kubernetes oracle source commit must be #{SOURCE_COMMIT}, got #{commit}" unless commit == SOURCE_COMMIT

    tag = capture!("git", "-C", source_root, "describe", "--tags", "--exact-match", "HEAD").strip
    raise OracleError, "Kubernetes oracle source tag must be #{KUBERNETES_VERSION}, got #{tag.inspect}" unless tag == KUBERNETES_VERSION

    dirty = capture!("git", "-C", source_root, "status", "--porcelain", "--untracked-files=no").strip
    raise OracleError, "Kubernetes oracle source checkout has tracked modifications" unless dirty.empty?

    MODULE_SOURCE_PATHS.each_value do |relative|
      module_root = ::File.join(source_root, relative)
      raise OracleError, "Kubernetes oracle source module is unavailable: #{relative}" unless ::File.file?(::File.join(module_root, "go.mod"))
    end
  end

  def normalize_requests(requests)
    seen = {}
    Array(requests).map do |request|
      entry = request.transform_keys(&:to_s)
      id = String(entry.fetch("id"))
      go_package = String(entry.fetch("go_package"))
      go_type = String(entry.fetch("go_type"))
      raise OracleError, "duplicate Kubernetes semantic oracle request #{id.inspect}" if seen.key?(id)
      raise OracleError, "invalid Go package for #{id.inspect}" unless go_package.match?(%r{\Ak8s\.io/[A-Za-z0-9_./-]+\z})
      raise OracleError, "invalid Go type for #{id.inspect}" unless go_type.match?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)

      seen[id] = true
      %w[raw_json unknown_json missing_json].each do |key|
        value = entry.fetch(key)
        raise OracleError, "oracle request #{id.inspect} #{key} must be a JSON string" unless value.is_a?(String)

        JSON.parse(value, max_nesting: 128)
      rescue JSON::ParserError => error
        raise OracleError, "oracle request #{id.inspect} #{key} is invalid JSON: #{error.message}"
      end
      validation_applicable = entry.fetch("validation_applicable", false)
      raise OracleError, "oracle request #{id.inspect} validation_applicable must be boolean" unless [true, false].include?(validation_applicable)

      validation_reason = entry.fetch("validation_reason", "")
      raise OracleError, "oracle request #{id.inspect} validation_reason must be a string" unless validation_reason.is_a?(String)

      validation_source_paths = entry.fetch("validation_source_paths", [])
      unless validation_source_paths.is_a?(Array) && validation_source_paths.all? { |path| path.is_a?(String) && !path.empty? }
        raise OracleError, "oracle request #{id.inspect} validation_source_paths must be an array of paths"
      end

      {
        "id" => id,
        "go_package" => go_package,
        "go_type" => go_type,
        "raw_json" => entry.fetch("raw_json"),
        "unknown_json" => entry.fetch("unknown_json"),
        "missing_json" => entry.fetch("missing_json"),
        "validation_applicable" => validation_applicable,
        "validation_reason" => validation_reason,
        "validation_source_paths" => validation_source_paths
      }.freeze
    end.sort_by { |entry| entry.fetch("id") }.freeze
  end

  def go_source(source_root, requests)
    mappings = requests.to_h { |request| [request.fetch("id"), [request.fetch("go_package"), request.fetch("go_type")]] }
    package_paths = mappings.values.map(&:first).uniq
    scheme_packages = package_paths.select { |path| scheme_package?(source_root, path) }
    imports = (package_paths + scheme_packages + [RUNTIME_PACKAGE]).uniq.sort
    aliases = imports.each_with_index.to_h { |path, index| [path, "oraclepkg#{index}"] }
    import_source = imports.map { |path| "\t#{aliases.fetch(path)} #{JSON.generate(path)}" }.join("\n")
    switch_source = mappings.sort.map do |id, (go_package, go_type)|
      "\tcase #{JSON.generate(id)}:\n\t\treturn &#{aliases.fetch(go_package)}.#{go_type}{}, nil"
    end.join("\n")
    scheme_source = scheme_packages.sort.map do |path|
      "\tif err := #{aliases.fetch(path)}.AddToScheme(scheme); err != nil {\n\t\treturn nil, fmt.Errorf(\"register #{path}: %w\", err)\n\t}"
    end.join("\n")

    source = <<~GO
      package main

      import (
      	"bytes"
      	"context"
      	"crypto/sha256"
      	"encoding/hex"
      	"encoding/json"
      	"errors"
      	"fmt"
      	"os"
       "reflect"
       "runtime"
       "strings"

      	field "k8s.io/apimachinery/pkg/util/validation/field"

      #{import_source}
      )

      type request struct {
      	ID                   string `json:"id"`
      	RawJSON              string `json:"raw_json"`
      	UnknownJSON          string `json:"unknown_json"`
      	MissingJSON          string `json:"missing_json"`
       ValidationApplicable bool   `json:"validation_applicable"`
       ValidationReason     string `json:"validation_reason"`
       ValidationSourcePaths []string `json:"validation_source_paths"`
      }

      type response struct {
      	GoVersion string   `json:"go_version"`
      	Results   []result `json:"results"`
      }

      type result struct {
      	ID      string `json:"id"`
      	GoType  string `json:"go_type"`
      	Passed  bool   `json:"passed"`
      	Error   string `json:"error,omitempty"`
      	JSON    jsonResult `json:"json"`
      	Defaulting defaultingResult `json:"defaulting"`
      	Validation validationResult `json:"validation"`
      }

      type jsonResult struct {
      	Accepted             bool                   `json:"accepted"`
      	RawSHA256            string                 `json:"raw_sha256"`
      	CanonicalSHA256      string                 `json:"canonical_sha256,omitempty"`
      	CanonicalJSON        string                 `json:"canonical_json,omitempty"`
      	Error                *errorResult           `json:"error,omitempty"`
      	Unknown              unknownJSONResult      `json:"unknown"`
      	StrictUnknown        strictUnknownResult    `json:"strict_unknown"`
      }

      type unknownJSONResult struct {
      	Accepted        bool         `json:"accepted"`
      	RawSHA256       string       `json:"raw_sha256"`
      	CanonicalSHA256 string       `json:"canonical_sha256,omitempty"`
      	CanonicalJSON   string       `json:"canonical_json,omitempty"`
      	FieldPreserved  bool         `json:"field_preserved"`
      	Error           *errorResult `json:"error,omitempty"`
      }

      type strictUnknownResult struct {
      	Accepted bool         `json:"accepted"`
      	Error    *errorResult `json:"error,omitempty"`
      }

      type defaultingResult struct {
      	Applicable       bool         `json:"applicable"`
      	Reason           string       `json:"reason,omitempty"`
      	SchemeRegistered bool         `json:"scheme_registered"`
      	BeforeSHA256     string       `json:"before_sha256,omitempty"`
      	AfterSHA256      string       `json:"after_sha256,omitempty"`
      	BeforeJSON       string       `json:"before_json,omitempty"`
      	AfterJSON        string       `json:"after_json,omitempty"`
      	Changed          bool         `json:"changed"`
      	Error            *errorResult `json:"error,omitempty"`
      }

      type validationResult struct {
      	Applicable       bool            `json:"applicable"`
      	Reason           string          `json:"reason,omitempty"`
      	Accepted         bool            `json:"accepted"`
      	Errors           []validationError `json:"errors"`
       MissingAccepted  bool            `json:"missing_accepted"`
       MissingErrors    []validationError `json:"missing_errors"`
       SourcePaths      []string        `json:"source_paths"`
       Error            *errorResult    `json:"error,omitempty"`
      }

      type errorResult struct {
      	Message string `json:"message"`
      	Field   string `json:"field,omitempty"`
      }

      type validationError struct {
      	Type   string `json:"type"`
      	Field  string `json:"field"`
      	Detail string `json:"detail,omitempty"`
      	Error  string `json:"error"`
      }

      func newValue(id string) (interface{}, error) {
      	switch id {
      #{switch_source}
      	default:
      		return nil, fmt.Errorf("unmapped schema %q", id)
      	}
      }

      func newScheme() (*#{aliases.fetch(RUNTIME_PACKAGE)}.Scheme, error) {
      	scheme := #{aliases.fetch(RUNTIME_PACKAGE)}.NewScheme()
      #{scheme_source}
      	return scheme, nil
      }

      func digest(value []byte) string {
      	sum := sha256.Sum256(value)
      	return hex.EncodeToString(sum[:])
      }

      func errorResultFor(err error) *errorResult {
      	if err == nil {
      		return nil
      	}
      	result := &errorResult{Message: err.Error()}
      	var typeError *json.UnmarshalTypeError
       if errors.As(err, &typeError) {
       		result.Field = typeError.Field
       	}
       const unknownPrefix = `json: unknown field "`
       if strings.HasPrefix(result.Message, unknownPrefix) {
        		field := strings.TrimPrefix(result.Message, unknownPrefix)
        		if end := strings.Index(field, `"`); end >= 0 {
        			result.Field = field[:end]
        		}
       }
       return result
      }

      func decodeJSON(raw string, value interface{}, strict bool) ([]byte, *errorResult) {
      	decoder := json.NewDecoder(bytes.NewBufferString(raw))
      if strict {
      		decoder.DisallowUnknownFields()
      	}
      if err := decoder.Decode(value); err != nil {
      		return nil, errorResultFor(err)
      	}
      encoded, err := json.Marshal(value)
      if err != nil {
      		return nil, errorResultFor(err)
      	}
      return encoded, nil
      }

      func containsUnknownField(encoded []byte) bool {
      	var object map[string]interface{}
      if json.Unmarshal(encoded, &object) != nil {
      		return false
      	}
      _, ok := object["m1FutureField"]
      return ok
      }

      func jsonProbe(input request, value interface{}) jsonResult {
      	result := jsonResult{RawSHA256: digest([]byte(input.RawJSON))}
      canonical, err := decodeJSON(input.RawJSON, value, false)
      if err != nil {
      		result.Error = err
      	} else {
      		result.Accepted = true
      		result.CanonicalSHA256 = digest(canonical)
      		result.CanonicalJSON = string(canonical)
      	}

      unknownValue, unknownErr := newValue(input.ID)
      if unknownErr != nil {
      		result.Unknown.Error = errorResultFor(unknownErr)
      		return result
      	}
      result.Unknown.RawSHA256 = digest([]byte(input.UnknownJSON))
      unknownCanonical, unknownDecodeErr := decodeJSON(input.UnknownJSON, unknownValue, false)
      if unknownDecodeErr != nil {
      		result.Unknown.Error = unknownDecodeErr
      } else {
      		result.Unknown.Accepted = true
      		result.Unknown.CanonicalSHA256 = digest(unknownCanonical)
      		result.Unknown.CanonicalJSON = string(unknownCanonical)
      		result.Unknown.FieldPreserved = containsUnknownField(unknownCanonical)
      }
      strictValue, strictValueErr := newValue(input.ID)
      if strictValueErr != nil {
      		result.StrictUnknown.Error = errorResultFor(strictValueErr)
      } else {
      		_, strictErr := decodeJSON(input.UnknownJSON, strictValue, true)
      		result.StrictUnknown.Accepted = strictErr == nil
      		result.StrictUnknown.Error = strictErr
      }
      return result
      }

      func schemeRegistered(scheme *#{aliases.fetch(RUNTIME_PACKAGE)}.Scheme, value interface{}) bool {
      	object, ok := value.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      	if !ok {
      		return false
      	}
      	_, _, err := scheme.ObjectKinds(object)
      return err == nil
      }

      func defaultProbe(input request, scheme *#{aliases.fetch(RUNTIME_PACKAGE)}.Scheme) defaultingResult {
      	result := defaultingResult{}
      value, err := newValue(input.ID)
      if err != nil {
      		result.Error = errorResultFor(err)
      		return result
      	}
      object, ok := value.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      if !ok {
      		result.Reason = fmt.Sprintf("%s.%s is not a runtime.Object; Scheme.Default has no applicable entrypoint", input.ID, reflect.TypeOf(value).Elem().Name())
      		return result
      	}
      result.Applicable = true
      result.SchemeRegistered = schemeRegistered(scheme, value)
      before, beforeErr := decodeJSON(input.RawJSON, value, false)
      if beforeErr != nil {
      		result.Error = beforeErr
      		return result
      	}
      // Decode into a fresh object so JSON acceptance and defaulting observe the
      // same fixture without sharing mutable state.
      value, err = newValue(input.ID)
      if err != nil {
      		result.Error = errorResultFor(err)
      		return result
      	}
      if _, decodeErr := decodeJSON(input.RawJSON, value, false); decodeErr != nil {
      		result.Error = decodeErr
      		return result
      	}
      object = value.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      scheme.Default(object)
      after, marshalErr := json.Marshal(value)
      if marshalErr != nil {
      		result.Error = errorResultFor(marshalErr)
      		return result
      	}
      result.BeforeSHA256 = digest(before)
      result.AfterSHA256 = digest(after)
      result.BeforeJSON = string(before)
      result.AfterJSON = string(after)
      result.Changed = !bytes.Equal(before, after)
      return result
      }

      func validationErrors(errors field.ErrorList) []validationError {
      	result := make([]validationError, 0, len(errors))
      	for _, item := range errors {
      		result = append(result, validationError{
      			Type: item.Type.String(), Field: item.Field, Detail: item.Detail, Error: item.Error(),
      		})
      	}
      	return result
      }

      func validationProbe(input request, scheme *#{aliases.fetch(RUNTIME_PACKAGE)}.Scheme) validationResult {
       result := validationResult{Errors: []validationError{}, MissingErrors: []validationError{}, SourcePaths: input.ValidationSourcePaths}
      if !input.ValidationApplicable {
      		result.Reason = input.ValidationReason
      		return result
      	}
      	value, err := newValue(input.ID)
      if err != nil {
      		result.Error = errorResultFor(err)
      		return result
      	}
      object, ok := value.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      if !ok {
      		result.Reason = fmt.Sprintf("%s is not a runtime.Object; Scheme.Validate has no applicable entrypoint", input.ID)
      		return result
      	}
      result.Applicable = true
      if _, decodeErr := decodeJSON(input.RawJSON, value, false); decodeErr != nil {
      		result.Error = decodeErr
      		return result
      	}
      object = value.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      valid := scheme.Validate(context.Background(), []string{}, object)
      result.Errors = validationErrors(valid)
      result.Accepted = len(valid) == 0

      missingValue, missingErr := newValue(input.ID)
      if missingErr != nil {
      		result.Error = errorResultFor(missingErr)
      		return result
      	}
      missingObject, missingObjectOK := missingValue.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      if !missingObjectOK {
      		result.Error = &errorResult{Message: fmt.Sprintf("%s is not a runtime.Object", input.ID)}
      		return result
      }
      if _, decodeErr := decodeJSON(input.MissingJSON, missingValue, false); decodeErr != nil {
      		result.Error = decodeErr
      		return result
      	}
      missingObject = missingValue.(#{aliases.fetch(RUNTIME_PACKAGE)}.Object)
      missing := scheme.Validate(context.Background(), []string{}, missingObject)
      result.MissingErrors = validationErrors(missing)
      result.MissingAccepted = len(missing) == 0
      return result
      }

      func compareOne(input request, scheme *#{aliases.fetch(RUNTIME_PACKAGE)}.Scheme) (result result) {
      	result.ID = input.ID
      	value, err := newValue(input.ID)
      if err != nil {
      		result.Error = err.Error()
      		return
      	}
      	result.GoType = reflect.TypeOf(value).String()
      	result.JSON = jsonProbe(input, value)
      	result.Defaulting = defaultProbe(input, scheme)
      	result.Validation = validationProbe(input, scheme)
      result.Passed = result.Error == "" && result.JSON.Error == nil && result.JSON.Unknown.Error == nil && result.Defaulting.Error == nil && result.Validation.Error == nil
      return
      }

      func main() {
      	var input []request
      	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
      		fmt.Fprintln(os.Stderr, "input:", err)
      		os.Exit(2)
      	}
      	scheme, err := newScheme()
      	if err != nil {
      		fmt.Fprintln(os.Stderr, "scheme:", err)
      		os.Exit(3)
      	}
      	results := make([]result, 0, len(input))
      	for _, item := range input {
      		func() {
      			defer func() {
      				if recovered := recover(); recovered != nil {
      					results = append(results, result{ID: item.ID, Passed: false, Error: fmt.Sprintf("panic: %v", recovered)})
      				}
      			}()
      			results = append(results, compareOne(item, scheme))
      		}()
      	}
      	encoder := json.NewEncoder(os.Stdout)
      	encoder.SetEscapeHTML(false)
      	if err := encoder.Encode(response{GoVersion: runtime.Version(), Results: results}); err != nil {
      		fmt.Fprintln(os.Stderr, "output:", err)
      		os.Exit(4)
      	}
      }
    GO
    [source, {
      "mappings" => mappings.transform_values { |go_package, type_name| "#{go_package}.#{type_name}" }.freeze,
      "scheme_packages" => scheme_packages,
      "validation_applicable_count" => requests.count { |request| request.fetch("validation_applicable") }
    }]
  end

  def scheme_package?(source_root, go_package)
    path = ::File.join(source_root, "staging/src", go_package)
    register_path = ::File.join(path, "register.go")
    return false unless ::File.file?(register_path)

    content = ::File.read(register_path)
    content.match?(/\bAddToScheme\s*=/) || content.match?(/\bfunc\s+AddToScheme\s*\(/)
  rescue Errno::ENOENT, Errno::EACCES
    false
  end

  def validation_registration(source_root:, go_package:, go_type:)
    package_root = ::File.join(source_root, "staging/src", go_package)
    validation_paths = Dir.glob(::File.join(package_root, "**/zz_generated.validations.go"))
    pattern = /AddValidationFunc\(\(\*#{Regexp.escape(go_type)}\)\(nil\)/
    matching_paths = validation_paths.select do |path|
      ::File.read(path).match?(pattern)
    end
    if matching_paths.empty?
      relative_paths = validation_paths.map { |path| path.delete_prefix("#{source_root}/") }
      relative_paths = [::File.join("staging/src", go_package)] if relative_paths.empty?
      reason = if validation_paths.empty?
                 "upstream source has no zz_generated.validations.go for #{go_package}.#{go_type}"
               else
                 "upstream generated validation package does not register #{go_type} with runtime.Scheme"
               end
      reason = "#{reason}; scanned #{relative_paths.empty? ? "package source" : relative_paths.join(", ")}"
      {"applicable" => false, "reason" => reason, "source_paths" => relative_paths}
    else
      {
        "applicable" => true,
        "reason" => "upstream generated validation is registered with runtime.Scheme",
        "source_paths" => matching_paths.map { |path| path.delete_prefix("#{source_root}/") }
      }
    end
  rescue Errno::ENOENT, Errno::EACCES => error
    raise OracleError, "cannot inspect validation registration for #{go_package}.#{go_type}: #{error.message}"
  end

  def execute_go(go:, source_root:, source:, requests:)
    Dir.mktmpdir("rubernetes-kubernetes-semantic-oracle-") do |directory|
      ::File.write(::File.join(directory, "main.go"), source)
      ::File.write(::File.join(directory, "go.mod"), go_mod(source_root))
      _tidy_stdout, tidy_stderr, tidy_status = Open3.capture3(
        {"GOWORK" => "off", "CGO_ENABLED" => "0"},
        go, "mod", "tidy",
        chdir: directory
      )
      unless tidy_status.success?
        detail = tidy_stderr.lines.last(20).join.strip
        raise OracleError, "Kubernetes semantic oracle dependency resolution failed (#{tidy_status.exitstatus}): #{detail}"
      end
      stdout, stderr, status = Open3.capture3(
        {"GOWORK" => "off", "CGO_ENABLED" => "0"},
        go, "run", ".",
        stdin_data: JSON.generate(requests),
        chdir: directory
      )
      unless status.success?
        detail = stderr.lines.last(30).join.strip
        raise OracleError, "Kubernetes semantic oracle Go helper failed (#{status.exitstatus}): #{detail}"
      end
      document = JSON.parse(stdout, max_nesting: 256)
      results = document.fetch("results")
      raise OracleError, "Kubernetes semantic oracle results must be an array" unless results.is_a?(Array)

      [results, String(document.fetch("go_version"))]
    end
  rescue JSON::ParserError => error
    raise OracleError, "Kubernetes semantic oracle returned invalid JSON: #{error.message}"
  end

  def go_mod(source_root)
    requirements = MODULES.map { |name| "\t#{name} v0.0.0" }.join("\n")
    replacements = MODULE_SOURCE_PATHS.map do |name, relative|
      "\t#{name} => #{::File.join(source_root, relative)}"
    end.join("\n")
    <<~MOD
      module rubernetes.dev/m1-semantic-oracle

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
