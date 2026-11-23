# frozen_string_literal: true

require "json"
require "open3"
require "yaml"

module Conformance
  # Helm intentionally leaves CRDs installed from a chart's crds/ directory
  # and those declared with its resource-policy annotation. In a disposable
  # test cluster, remove empty CRDs left by the installation or its smoke fixture.
  class K6ProjectCRDCleanup
    def initialize(kubectl:, helm:, kubeconfig:, namespace:, helm_env:)
      @kubectl = [kubectl, "--kubeconfig", kubeconfig, "--request-timeout=20s"]
      @helm = [helm_env, helm, "--kubeconfig", kubeconfig, "--namespace", namespace]
      @namespace = namespace
    end

    def names(charts, chart_directory)
      charts.flat_map do |chart|
        archive = File.join(chart_directory, chart.fetch("chart_package"))
        names = crd_names("show", "crds", archive) + crd_names("get", "manifest", chart.fetch("name"))
        if (value = chart["crd_inventory_value"])
          # Some charts ship the names as templates but install full schemas
          # from a version-matched hook image. Only render this inventory.
          names.concat(crd_names("template", chart.fetch("name"), archive, "--set", value))
        end
        names.concat(chart.fetch("fixture_crds", []))
      end.uniq
    end

    def run(names, before, installed, after, failed_releases: nil, created: [])
      return [] if before.nil? || installed.nil? || after.nil?

      preexisting_names = before.keys.map(&:first)
      after.filter_map do |(name, uid), record|
        original = installed[[name, uid]]
        next if uid.to_s.empty? || !original
        next unless names.include?(name) && !preexisting_names.include?(name)
        next if failed_releases && !created.include?([name, uid]) && !same_release?(original, record, failed_releases)

        remove(record)
      end
    end

    private

    # Static CRDs are outside Helm's release manifest and have no release
    # metadata. After a failed install a new matching name alone cannot
    # establish that Helm was its first writer.
    def same_release?(original, current, releases)
      release = original.dig("metadata", "annotations", "meta.helm.sh/release-name")
      releases.include?(release) && [original, current].all? do |record|
        record.dig("metadata", "annotations", "meta.helm.sh/release-name") == release &&
          record.dig("metadata", "annotations", "meta.helm.sh/release-namespace") == @namespace &&
          record.dig("metadata", "labels", "app.kubernetes.io/managed-by") == "Helm"
      end
    end

    def crd_names(*)
      out, _, status = Open3.capture3(*@helm, *, binmode: true)
      return [] unless status.success?

      out.force_encoding(Encoding::UTF_8).split(/^---\s*$/).filter_map do |document|
        object = YAML.safe_load(document)
        object.dig("metadata", "name") if object.is_a?(Hash) && object["kind"] == "CustomResourceDefinition"
      rescue Psych::Exception
        nil
      end
    end

    def remove(record)
      metadata = record.fetch("metadata")
      name = metadata.fetch("name")
      instances, error, status = Open3.capture3(*@kubectl, "get", name, "--all-namespaces", "-o", "json", binmode: true)
      return failure(name, error) unless status.success?
      return failure(name, "custom resources still exist") unless JSON.parse(instances.force_encoding(Encoding::UTF_8)).fetch("items").empty?

      conditions = metadata.slice("uid", "resourceVersion")
      return failure(name, "CRD has no server identity") unless conditions.size == 2

      body = JSON.generate("apiVersion" => "v1", "kind" => "DeleteOptions", "preconditions" => conditions)
      route = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/#{name}"
      _, error, status = Open3.capture3(*@kubectl, "delete", "--raw=#{route}", "--filename=-", stdin_data: body, binmode: true)
      return failure(name, error) unless status.success?

      _, error, status = Open3.capture3(*@kubectl, "wait", "--for=delete", "customresourcedefinition/#{name}", "--timeout=20s", binmode: true)
      status.success? ? {"name" => name, "passed" => true} : failure(name, error)
    rescue JSON::ParserError => error
      failure(name, error.message)
    end

    def failure(name, error)
      {"name" => name, "passed" => false, "error" => error.dup.force_encoding(Encoding::UTF_8).scrub.lines.last(5).join.strip}
    end
  end
end
