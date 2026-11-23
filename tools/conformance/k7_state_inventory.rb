# frozen_string_literal: true

require "json"
require "open3"
require "uri"

module Conformance
  class K7StateInventory
    class Unreadable < StandardError; end

    BUILTIN_RESOURCES = "all,namespaces,nodes,configmaps,secrets,pvc,pv,volumeattachments"
    RBAC_VERSION = "rbac.authorization.k8s.io/v1"
    RBAC_RESOURCES = {"roles" => "Role", "rolebindings" => "RoleBinding", "clusterroles" => "ClusterRole",
                      "clusterrolebindings" => "ClusterRoleBinding"}.freeze
    CRD_VERSION = "apiextensions.k8s.io/v1"
    CRD_PATH = "/apis/#{CRD_VERSION}/customresourcedefinitions".freeze

    def initialize(kubectl, kubeconfig)
      @command = [kubectl, "--request-timeout=10s", "--kubeconfig", kubeconfig, "get"]
      @discovery = {}
    end

    def each_item(&)
      crds = []
      each_page_item(CRD_PATH, CRD_VERSION, "CustomResourceDefinition") { |crd| crds << crd }
      custom_kinds = crds.to_set do |crd|
        spec = crd.fetch("spec")
        [spec.fetch("group"), spec.fetch("names").fetch("kind")]
      end
      document = read(BUILTIN_RESOURCES, BUILTIN_RESOURCES, "--all-namespaces", "-o", "json", "--show-managed-fields")
      list_items(document, BUILTIN_RESOURCES).each do |item|
        version = item.fetch("apiVersion")
        group = version.rpartition("/").first
        yield item unless custom_kinds.include?([group, item.fetch("kind")])
      end
      RBAC_RESOURCES.each do |resource, kind|
        each_page_item("/apis/#{RBAC_VERSION}/#{resource}", RBAC_VERSION, kind, &)
      end
      crds.each do |crd|
        yield crd
        each_custom_resource(crd, &) if self.class.established?(crd)
      end
    rescue KeyError, TypeError
      raise Unreadable, "invalid object in the API inventory"
    end

    def self.established?(crd)
      Array(crd.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Established True] }
    end

    private

    def each_custom_resource(crd, &)
      spec = crd.fetch("spec")
      group = spec.fetch("group")
      names = spec.fetch("names")
      plural = names.fetch("plural")
      kind = names.fetch("kind")
      versions = spec.fetch("versions").select { |version| version["served"] == true }
      storage = versions.find { |version| version["storage"] == true } || versions.first
      raise Unreadable, "no served version for #{plural}.#{group}" unless storage

      versions.each do |version|
        version_path = "/apis/#{group}/#{version.fetch("name")}"
        resources = @discovery[version_path] ||= read_discovery(version_path)
        entry = resources.find { |resource| resource["name"] == plural }
        unless entry && entry["kind"] == kind && entry["namespaced"] == (spec.fetch("scope") == "Namespaced") && Array(entry["verbs"]).include?("list")
          raise Unreadable, "#{plural} is not listable in discovery at #{version_path}"
        end
      end
      api_version = "#{group}/#{storage.fetch("name")}"
      each_page_item("/apis/#{api_version}/#{plural}", api_version, kind, &)
    end

    def read_discovery(path)
      discovery = read(path, "--raw", path)
      resources = discovery["resources"]
      unless discovery["groupVersion"] == path.delete_prefix("/apis/") && resources.is_a?(Array) && resources.all?(Hash)
        raise Unreadable, "invalid discovery response at #{path}"
      end

      resources
    end

    def each_page_item(path, api_version, kind)
      params = {"limit" => "500"}
      tokens = Set.new
      loop do
        document = read(path, "--raw", "#{path}?#{URI.encode_www_form(params)}")
        list_items(document, path).each do |item|
          if (item.key?("apiVersion") && item["apiVersion"] != api_version) || (item.key?("kind") && item["kind"] != kind)
            raise Unreadable, "unexpected item type in #{path}"
          end

          # Kubernetes can omit TypeMeta from items of typed List responses.
          yield item.merge("apiVersion" => api_version, "kind" => kind)
        end
        token = document.dig("metadata", "continue")
        break if token.nil? || token == ""
        raise Unreadable, "invalid continue token for #{path}" unless token.is_a?(String) && tokens.add?(token)

        params["continue"] = token
      end
    end

    def list_items(document, label)
      items = document["items"]
      raise Unreadable, "invalid resource list for #{label}" unless items.is_a?(Array) && items.all?(Hash)

      items
    end

    def read(label, *)
      out, _stderr, status = Open3.capture3(*@command, *)
      # Command errors and parse exceptions may contain resource bodies. Keep
      # only the operation and resource in the evidence.
      raise Unreadable, "could not read #{label} (kubectl exit #{status.exitstatus})" unless status.success?

      document = JSON.parse(out, max_nesting: 512)
      raise Unreadable, "invalid API response for #{label}" unless document.is_a?(Hash)

      document
    rescue JSON::ParserError, SystemCallError
      raise Unreadable, "could not read #{label}"
    end
  end
end
