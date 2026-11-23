# frozen_string_literal: true

require "json"
require "open3"
require "tempfile"

require_relative "../../lib/rubernetes/image"

module Conformance
  module K0
    # The upstream --list-images command prints GetImageConfigs(). Invoke
    # that same function in the vetted checkout so the evidence has the
    # exact upstream registry defaults and embedded CSI manifests.
    module E2EImages
      Image = Rubernetes::Image
      INVENTORY = <<~GO
        package main

        import (
          "fmt"
          "k8s.io/kubernetes/test/utils/image"
        )

        func main() {
          for _, config := range image.GetImageConfigs() {
            fmt.Println(config.GetE2EImage())
          }
        }
      GO
      INVENTORY_ENV = {"KUBE_TEST_REPO" => nil, "KUBE_TEST_REPO_LIST" => nil, "GOFLAGS" => nil, "GOWORK" => nil}.freeze

      # These are explicit test inputs in the pinned upstream source. The
      # registry-failure tests expect an invalid image. The private image is
      # exercised by GCE tests or the provider plugin test, not by the stock
      # Linux profile, which supplies no provider credentials.
      SPECIAL_REFERENCES = {
        "invalid.registry.k8s.io/invalid/alpine:3.1" => {
          "status" => "expected_pull_failure", "source" => "test/e2e/common/node/runtime.go"
        }.freeze,
        "gcr.io/k8s-authenticated-test/agnhost:2.6" => {
          "status" => "requires_provider_credentials", "source" => "test/e2e/common/node/image_credential_provider.go"
        }.freeze
      }.freeze

      class InventoryError < StandardError; end

      module_function

      def verify(source_root, platform, registry_client: default_client)
        images = observe(references(source_root), platform, registry_client: registry_client)
        {
          "id" => "upstream_image_inventory",
          "passed" => images.values.none? { |image| image["status"] == "unresolved" },
          "inventory_source" => "test/utils/image.GetImageConfigs",
          "images" => images
        }
      rescue InventoryError => error
        {"id" => "upstream_image_inventory", "passed" => false, "error" => error.message, "images" => {}}
      end

      def references(source_root)
        Tempfile.create(["rubernetes-k0-e2e-images", ".go"]) do |program|
          program.write(INVENTORY)
          program.flush
          stdout, _stderr, status = Open3.capture3(INVENTORY_ENV, "go", "run", "-mod=vendor", program.path, chdir: source_root)
          raise InventoryError, "upstream image inventory did not run from the pinned source (exit #{status.exitstatus})" unless status.success?

          references = stdout.lines(chomp: true).reject(&:empty?).uniq.sort
          raise InventoryError, "upstream image inventory is empty" if references.empty?

          references
        end
      rescue SystemCallError
        raise InventoryError, "could not run the upstream source image inventory"
      end

      def default_client
        ->(reference) { Image::RegistryClient.new(reference, open_timeout: 8, read_timeout: 16) }
      end

      def observe(references, platform, registry_client: default_client)
        references.each_slice(8).flat_map do |slice|
          slice.map do |reference|
            Thread.new { [reference, resolve(reference, platform, registry_client)] }
          end.map(&:value)
        end.to_h
      end

      def resolve(tagged, platform, registry_client)
        special = SPECIAL_REFERENCES[tagged]
        return special if special

        reference = Image::Reference.parse(tagged)
        os, arch, variant = platform.split("/")
        client = registry_client.call(reference)
        manifest = client.manifest(reference, os: os, architecture: arch, variant: variant)
        if manifest.index_digest.nil?
          config = JSON.parse(client.fetch_config(reference, manifest: manifest))
          unless config["os"] == os && config["architecture"] == arch && (!variant || config["variant"] == variant)
            return {"status" => "unresolved", "error" => "single manifest does not have the requested platform"}
          end
        end
        {"status" => "resolved", "digest" => (manifest.index_digest || manifest.digest).to_s, "platform_digest" => manifest.digest.to_s}
      rescue Image::Error, JSON::ParserError => error
        {"status" => "unresolved", "error" => error.message}
      end

      def stability(previous, platform, registry_client: default_client)
        latest = observe(previous.keys, platform, registry_client: registry_client)
        mismatches = previous.keys.filter_map do |reference|
          before = previous.fetch(reference)
          after = latest.fetch(reference)
          next if before == after && after["status"] != "unresolved"

          {"reference" => reference, "before" => before, "after" => after}
        end
        {"id" => "upstream_image_stability", "passed" => !previous.empty? && mismatches.empty?, "mismatches" => mismatches}
      end
    end
  end
end
