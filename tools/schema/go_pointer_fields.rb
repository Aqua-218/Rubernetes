#!/usr/bin/env ruby
# frozen_string_literal: true

# Derive the Go pointer-field table used by the Kubernetes protobuf codec.
#
# go-to-protobuf emits every scalar as `optional`, so the wire format cannot
# distinguish a Go pointer field (nil vs explicit zero) from a non-pointer field
# whose zero value is always marshaled.  encoding/json omits the latter under
# `omitempty` while keeping an explicit pointer zero.  The codec therefore needs
# to know which fields are pointers in the pinned Go sources; this tool reads
# those sources and writes a checked-in Ruby constant.
#
#   ruby tools/schema/go_pointer_fields.rb --source /path/to/kubernetes-v1.36.2
#
# The output is bound to the pinned upstream commit recorded in
# schema/kubernetes/v1.36.2/sources.json and verified against the pinned
# protobuf descriptors, so a stale or foreign checkout cannot produce a table.

require "digest"
require "json"
require "optparse"
require "pathname"

ROOT = Pathname.new(File.expand_path("../..", __dir__)) unless defined?(ROOT)
$LOAD_PATH.unshift(ROOT.join("lib").to_s) unless $LOAD_PATH.include?(ROOT.join("lib").to_s)
require "rubernetes/schema/codec"
require "rubernetes/schema/codec/proto_descriptor"

module GoPointerFields
  class Error < StandardError; end

  CORPUS = ROOT.join("schema/kubernetes/v1.36.2").freeze
  OUTPUT = ROOT.join("lib/rubernetes/schema/codec/kubernetes_pointer_fields.rb").freeze
  # Go packages whose types are served by the pinned protobuf corpus.  The
  # proto package is the Go import path with `/` and `-` replaced.
  SOURCE_PACKAGES = {
    "staging/src/k8s.io/api" => "k8s.io.api",
    "staging/src/k8s.io/apimachinery/pkg/apis/meta/v1" => "k8s.io.apimachinery.pkg.apis.meta.v1",
    "staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1" =>
      "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1",
    "staging/src/k8s.io/kube-aggregator/pkg/apis/apiregistration/v1" =>
      "k8s.io.kube_aggregator.pkg.apis.apiregistration.v1"
  }.freeze
  STRUCT_START = /\Atype\s+([A-Z][A-Za-z0-9]*)\s+struct\s*\{\s*\z/
  # A named field: exported name, type, and the struct tag.
  FIELD = /\A([A-Z][A-Za-z0-9]*)\s+(\*?[A-Za-z0-9_.\[\]]+)\s+`([^`]*)`/
  # An embedded struct flattened into the parent JSON object.
  INLINE = /\A(\*?[A-Za-z0-9_.]+)\s+`([^`]*json:",inline"[^`]*)`/
  JSON_TAG = /json:"([^"]*)"/
  PROTOBUF_NAME = /protobuf:"[^"]*\bname=([A-Za-z0-9_]+)/

  module_function

  def run(argv)
    options = {source: nil, check: false}
    OptionParser.new do |parser|
      parser.banner = "Usage: go_pointer_fields.rb --source KUBERNETES_CHECKOUT [--check]"
      parser.on("--source PATH", "Kubernetes v1.36.2 source checkout") { |value| options[:source] = value }
      parser.on("--check", "verify the checked-in table instead of writing it") { options[:check] = true }
    end.parse!(argv)
    raise Error, "--source is required" if options[:source].nil?

    source = Pathname.new(File.expand_path(options[:source]))
    commit = verify_source!(source)
    table = build_table(source)
    rendered = render(table, commit)
    if options[:check]
      current = OUTPUT.file? ? OUTPUT.read : ""
      raise Error, "#{OUTPUT} is stale; rerun without --check" unless current == rendered

      puts "#{OUTPUT.relative_path_from(ROOT)} is current (#{table.length} messages)"
    else
      OUTPUT.write(rendered)
      puts "wrote #{OUTPUT.relative_path_from(ROOT)} (#{table.length} messages)"
    end
    0
  end

  def pinned_commit
    manifest = JSON.parse(CORPUS.join("sources.json").read)
    manifest.fetch("source").fetch("commit")
  end

  # The checkout is only usable when its Go sources match the pinned commit's
  # generated protobuf, which is the corpus this project treats as normative.
  def verify_source!(source)
    commit = pinned_commit
    SOURCE_PACKAGES.each_key do |relative|
      raise Error, "source checkout lacks #{relative}" unless source.join(relative).directory?
    end
    manifest = JSON.parse(CORPUS.join("sources.json").read)
    manifest.fetch("sources").each do |entry|
      next unless entry["kind"] == "protobuf"

      upstream = source.join(entry.fetch("upstream_path"))
      raise Error, "source checkout lacks #{entry.fetch("upstream_path")}" unless upstream.file?

      digest = Digest::SHA256.file(upstream.to_s).hexdigest
      raise Error, "#{entry.fetch("upstream_path")} differs from the pinned commit #{commit}" unless digest == entry.fetch("source_sha256")
    end

    commit
  end

  def build_table(source)
    registry = Rubernetes::Schema::Codec::ProtoDescriptor::Registry.load(CORPUS.join("protobuf").to_s)
    table = {}
    SOURCE_PACKAGES.each do |relative, proto_prefix|
      Dir.glob(source.join(relative, "**", "types*.go").to_s).each do |path|
        directory = Pathname.new(path).dirname
        suffix = directory.relative_path_from(source.join(relative)).to_s
        package = suffix == "." ? proto_prefix : "#{proto_prefix}.#{suffix.tr("/", ".").tr("-", "_")}"
        parse_file(path).each do |struct_name, shape|
          full_name = "#{package}.#{struct_name}"
          descriptor = registry.resolve(full_name)
          next if descriptor.nil?

          entry = {
            "pointer" => shape.fetch(:pointer).select { |json_name| wire_field?(descriptor, json_name) }.sort,
            "zero" => shape.fetch(:zero).select { |json_name| wire_field?(descriptor, json_name) }.sort,
            "inline" => shape.fetch(:inline).select { |proto_name| descriptor.fields_by_name.key?(proto_name) }.sort,
            "omitzero" => shape.fetch(:omitzero).select { |json_name| wire_field?(descriptor, json_name) }.sort
          }
          table[full_name] = entry if entry.values.any? { |names| !names.empty? }
        end
      end
    end
    table.sort.to_h
  end

  # JSON Schema keeps spellings ($ref, x-kubernetes-*) that go-to-protobuf
  # rewrites into proto identifiers; the codec applies the same rewrite.
  def wire_field?(descriptor, json_name)
    return true if descriptor.fields_by_json_name.key?(json_name)

    proto_name = json_name.delete_prefix("$")
    if json_name.start_with?("x-kubernetes-")
      proto_name = json_name.split("-").each_with_index.map { |part, index| index.zero? ? part : part.capitalize }.join
    end
    descriptor.fields_by_name.key?(proto_name)
  end

  def self.lower_camel(name)
    name.sub(/\A[A-Z]+(?=[A-Z][a-z]|\z)/, &:downcase).sub(/\A[A-Z]/, &:downcase)
  end

  # Returns struct name => {pointer:, zero:, inline:} where +pointer+ and
  # +zero+ hold JSON names (pointer fields, and non-pointer fields serialized
  # without omitempty) and +inline+ holds proto field names of embedded
  # structs flattened into the parent JSON object.
  def parse_file(path)
    structs = {}
    current = nil
    File.foreach(path, chomp: true) do |raw|
      line = raw.strip
      if current.nil?
        match = STRUCT_START.match(line)
        current = [match[1], {pointer: [], zero: [], inline: [], omitzero: []}] if match
        next
      end
      if line == "}"
        structs[current[0]] = current[1]
        current = nil
        next
      end
      inline = INLINE.match(line)
      if inline
        proto_name = PROTOBUF_NAME.match(inline[2])
        # `EphemeralContainerCommon `json:",inline" protobuf:"bytes,1,req"``
        # carries no name=: gogo then names the field after the Go type,
        # lower-camel ("ephemeralContainerCommon").  Skipping it left every
        # protobuf-encoded ephemeral container without its name/image.
        name = proto_name ? proto_name[1] : lower_camel(inline[1].delete_prefix("*").split(".").last)
        current[1][:inline] << name
        next
      end
      match = FIELD.match(line)
      next unless match

      tag = JSON_TAG.match(match[3])
      next if tag.nil?

      json_name, *options = tag[1].split(",")
      next if json_name.nil? || json_name.empty? || json_name == "-"

      current[1][:omitzero] << json_name if options.include?("omitzero")
      if match[2].start_with?("*")
        current[1][:pointer] << json_name
      elsif !options.include?("omitempty")
        current[1][:zero] << json_name
      end
    end
    structs
  end

  def render(table, commit)
    lines = []
    lines << "# frozen_string_literal: true"
    lines << ""
    lines << "# Generated by tools/schema/go_pointer_fields.rb from kubernetes/kubernetes"
    lines << "# commit #{commit} (v1.36.2); do not edit by hand."
    lines << "#"
    lines << "# Records the Go struct shape the protobuf wire format cannot express:"
    lines << "#   pointer: fields declared as Go pointers (nil is omitted, an explicit"
    lines << "#            zero is kept by encoding/json);"
    lines << "#   zero:    non-pointer fields serialized without omitempty (their zero"
    lines << "#            value stays visible in JSON);"
    lines << "#   inline:  embedded structs flattened into the parent JSON object;"
    lines << "#   omitzero: struct fields whose zero value encoding/json omits."
    lines << "# Every other scalar is written unconditionally on the wire and omitted"
    lines << "# from JSON when zero."
    lines << "module Rubernetes"
    lines << "  module Schema"
    lines << "    class Codec"
    lines << "      module KubernetesPointerFields"
    lines << "        SOURCE_COMMIT = #{commit.inspect}.freeze"
    lines << "        EMPTY = [].freeze"
    lines << "        TABLE = {"
    table.each do |message, entry|
      parts = entry.map do |key, names|
        "#{key}: #{names.empty? ? "EMPTY" : "%w[#{names.join(" ")}].freeze"}"
      end
      lines << "          #{message.inspect} => {#{parts.join(", ")}}.freeze,"
    end
    lines[-1] = lines[-1].chomp(",") unless table.empty?
    lines << "        }.freeze"
    lines << ""
    lines << "        def self.pointer?(message_name, json_name)"
    lines << "          entry = TABLE[message_name.to_s]"
    lines << "          !entry.nil? && entry.fetch(:pointer).include?(json_name.to_s)"
    lines << "        end"
    lines << ""
    lines << "        def self.keep_zero?(message_name, json_name)"
    lines << "          entry = TABLE[message_name.to_s]"
    lines << "          !entry.nil? && entry.fetch(:zero).include?(json_name.to_s)"
    lines << "        end"
    lines << ""
    lines << "        def self.inline?(message_name, proto_name)"
    lines << "          entry = TABLE[message_name.to_s]"
    lines << "          !entry.nil? && entry.fetch(:inline).include?(proto_name.to_s)"
    lines << "        end"
    lines << ""
    lines << "        def self.omitzero?(message_name, json_name)"
    lines << "          entry = TABLE[message_name.to_s]"
    lines << "          !entry.nil? && entry.fetch(:omitzero).include?(json_name.to_s)"
    lines << "        end"
    lines << "      end"
    lines << "    end"
    lines << "  end"
    lines << "end"
    "#{lines.join("\n")}\n"
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    exit GoPointerFields.run(ARGV)
  rescue GoPointerFields::Error => error
    warn "go_pointer_fields: #{error.message}"
    exit 1
  end
end
