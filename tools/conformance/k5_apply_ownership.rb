# frozen_string_literal: true

require "json"
require_relative "../../lib/rubernetes/client"

module Conformance
  # Follow the field disputed by the kubectl conflict case through a forced
  # preview, a committed takeover, and pruning when its new owner omits it.
  module K5ApplyOwnership
    module_function

    def run(kubeconfig, fixture)
      client = Rubernetes::Client::HTTPClient.new(context: Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve, read_timeout: 15)
      path = "/api/v1/namespaces/default/configmaps/#{fixture}"
      trace = []
      original = exchange(client, trace, "GET", path)
      data = {"a" => "conflicting-write", "c" => "d"}
      manifest = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => fixture}, "data" => data.slice("a")}
      options = {"fieldManager" => "k5-apply", "force" => "true"}
      headers = {"Content-Type" => "application/apply-patch+yaml"}
      preview = exchange(client, trace, "PATCH", path, headers: headers, query: options.merge("dryRun" => "All"), body: manifest)
      after_preview = exchange(client, trace, "GET", path)
      raise "forced dry run changed the stored object" unless original == after_preview
      raise "initial conflict changed the stored field" unless original.fetch("data") == {"a" => "b", "c" => "d"}

      updated = exchange(client, trace, "PATCH", path, headers: headers, query: options, body: manifest)
      verify_write(original, updated, exchange(client, trace, "GET", path))
      pruned = exchange(client, trace, "PATCH", path, headers: headers, query: options.except("force"), body: manifest.except("data"))
      verify_write(updated, pruned, exchange(client, trace, "GET", path))
      unless preview.fetch("data") == data && updated.fetch("data") == data && pruned.fetch("data") == data.except("a")
        raise "force apply or field omission changed the wrong ConfigMap data"
      end

      {"exit_status" => 0, "stdout" => JSON.generate([original, preview, updated, pruned]), "stderr" => "", "trace" => trace}
    rescue Rubernetes::Client::Error, RuntimeError, KeyError, ArgumentError, JSON::ParserError => error
      {"exit_status" => 1, "stdout" => "", "stderr" => error.message, "trace" => trace}
    ensure
      client&.close
    end

    def exchange(client, trace, method, path, **options)
      response = client.request(method, path, **options)
      body = response.json
      trace << {"method" => method, "path" => path, **options.slice(:query, :headers, :body), "status" => response.status, "response" => body}
      raise "#{method} #{path} returned HTTP #{response.status}" unless response.status == 200

      body
    end

    def verify_write(previous, written, readback)
      raise "apply response differs from stored ConfigMap" unless written == readback

      before = previous.fetch("metadata")
      after = written.fetch("metadata")
      return if before.fetch("uid") == after.fetch("uid") && Integer(after.fetch("resourceVersion")) > Integer(before.fetch("resourceVersion"))

      raise "apply changed object identity or failed to advance resourceVersion"
    end
  end
end
