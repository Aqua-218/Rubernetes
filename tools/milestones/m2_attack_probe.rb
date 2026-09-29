#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m2_probe_support"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "digest"
require "rubygems/package"
require "stringio"
require "tmpdir"
require "zlib"

require "rubernetes/image"

module M2AttackProbe
  module_function

  MEDIA_TYPE = Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP

  def run_case(id)
    Dir.mktmpdir("rubernetes-m2-attack-") do |directory|
      root = File.join(directory, "root")
      outside = File.join(directory, "escape")
      layer = case id
              when "image_digest_mismatch"
                gzip_layer { |tar| tar.add_file_simple("safe", 0o600, 4) { |io| io.write("safe") } }
              when "path_traversal"
                gzip_layer { |tar| tar.add_file_simple("../escape", 0o600, 1) { |io| io.write("x") } }
              when "whiteout_escape"
                # A whiteout whose target resolves to the root is rejected;
                # accepting it would let an untrusted layer remove the whole
                # rootfs rather than one child entry.
                gzip_layer { |tar| tar.add_file_simple(".wh..", 0o600, 0) {} }
              when "symlink_race"
                gzip_layer do |tar|
                  tar.add_symlink("redirect", "target", 0o777)
                  tar.add_file_simple("redirect/created", 0o600, 1) { |io| io.write("x") }
                end
              else
                raise ArgumentError, "unknown attack #{id}"
              end

      expected = case id
                when "image_digest_mismatch" then Rubernetes::Image::DigestMismatch
                when "path_traversal", "whiteout_escape", "symlink_race" then Rubernetes::Image::SecurityError
                end
      error = nil
      begin
        digest = id == "image_digest_mismatch" ? "sha256:#{"0" * 64}" : digest_for(layer)
        Rubernetes::Image::LayerExtractor.new(root).extract(layer, digest: digest, media_type: MEDIA_TYPE)
      rescue expected => caught
        error = caught
      end
      raise "#{id} was accepted" unless error
      raise "#{id} escaped the extraction root" if File.exist?(outside)

      observable = {
        "id" => id,
        "rejected_class" => error.class.name,
        "message" => error.message,
        "root_entries" => Dir.children(root).sort
      }
      observable.merge("root_empty" => Dir.empty?(root))
    end
  end

  def gzip_layer
    tar_io = StringIO.new("".b)
    Gem::Package::TarWriter.new(tar_io) { |tar| yield tar }
    output = StringIO.new("".b)
    gzip = Zlib::GzipWriter.new(output)
    gzip.write(tar_io.string)
    gzip.close
    output.string
  end

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end
end

M2ProbeSupport.run_probe("m2_oci_attack_corpus", "m2-attack-probe") do |_current, _input|
  cases = M2Gate::REQUIRED_ATTACKS.map do |id|
    observable = M2AttackProbe.run_case(id)
    {
      "id" => id,
      "category" => id,
      "status" => "PASS",
      "passed" => true,
      "attempt_count" => 1,
      "failure_count" => 0,
      "fail_closed" => true,
      "measurement_source" => "production_image_layer_extractor",
      "adapter_class" => "Rubernetes::Image::LayerExtractor",
      "observable_sha256" => Digest::SHA256.hexdigest(JSON.generate(observable)),
      "observable" => observable
    }
  end
  {
    "passed" => true,
    "measurement_source" => "production_image_layer_extractor",
    "cases" => cases,
    "coverage_count" => cases.length,
    "case_count" => cases.length
  }
end
