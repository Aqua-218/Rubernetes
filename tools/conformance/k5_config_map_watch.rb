# frozen_string_literal: true

require "json"
require_relative "../../lib/rubernetes/client"

module Conformance
  # Replay a ConfigMap's complete lifetime from a real LIST cursor. Revisions
  # differ across clusters, but each event must identify the exact write.
  module K5ConfigMapWatch
    COLLECTION = "/api/v1/namespaces/default/configmaps"

    module_function

    def run(kubeconfig, name)
      context = Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve
      client = Rubernetes::Client::HTTPClient.new(context: context, read_timeout: 15)
      selector = {"fieldSelector" => "metadata.name=#{name}"}
      list = checked(client.request("GET", COLLECTION, query: selector), 200)
      raise "fixture already exists" unless list.fetch("items").empty?

      cursor = list.fetch("metadata").fetch("resourceVersion")
      manifest = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => name}, "data" => {"message" => "first"}}
      created = checked(client.request("POST", COLLECTION, query: {"fieldManager" => "k5-watch-create"}, body: manifest), 201)
      uid = created.fetch("metadata").fetch("uid")
      path = "#{COLLECTION}/#{name}"
      previews = dry_run_operations(client, path, selector, manifest, created)
      updated = checked(client.request("PATCH", path, body: {"data" => {"message" => "second"}},
                                                      headers: {"Content-Type" => "application/merge-patch+json"},
                                                      query: {"fieldManager" => "k5-watch-patch"}), 200)
      options = {"apiVersion" => "v1", "kind" => "DeleteOptions", "preconditions" => {"uid" => uid}}
      checked(client.request("DELETE", path, body: options), 200)
      deleted = true
      response = client.request("GET", COLLECTION, query: selector.merge("watch" => "true", "timeoutSeconds" => "3", "resourceVersion" => cursor))
      raise "watch returned HTTP #{response.status}" unless response.status == 200

      events = response.body.lines.reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }
      check_events(events, cursor, name, created, updated)
      type = response["content-type"].to_s
      raise "unexpected watch media type #{type.inspect}" unless type.split(";").first == "application/json"

      # K5's general normalizer compares managedFields by shape. Expose actual
      # ownership across the write sequence while omitting only wall-clock time.
      ownership = events.map { |event| event.fetch("object").fetch("metadata").fetch("managedFields").map { |entry| entry.except("time") } }
      {"exit_status" => 0, "stdout" => JSON.generate("events" => events, "fieldOwnership" => ownership, "dryRun" => previews), "stderr" => "",
       "http_status" => response.status, "content_type" => type}
    rescue StandardError => error
      {"exit_status" => 1, "stdout" => "", "stderr" => error.message}
    ensure
      begin
        client.request("DELETE", "#{COLLECTION}/#{name}", body: {"preconditions" => {"uid" => uid}}) if uid && !deleted
      ensure
        client&.close
      end
    end

    # Reuse the active LIST cursor. A dry-run write that increments this
    # object's revision or produces a watch event breaks the lifetime check.
    def dry_run_operations(client, path, selector, manifest, created)
      body = {"apiVersion" => "v1", "kind" => "DeleteOptions", "dryRun" => ["All"]}
      duplicate = checked(client.request("POST", COLLECTION, body: manifest, query: {"dryRun" => "All"}), 409)
      invalid = checked(client.request("DELETE", path, body: body.merge("dryRun" => ["Other"])), 422)
      deleted = checked(client.request("DELETE", path, body: body), 200)
      list = checked(client.request("DELETE", COLLECTION, query: selector, body: body), 200)
      stored = checked(client.request("GET", path), 200)
      raise "dry-run delete changed the stored ConfigMap" unless stored == created
      unless list.fetch("kind") == "ConfigMapList" && list.fetch("items") == [created.except("kind", "apiVersion")]
        raise "dry-run collection response lost the selected object"
      end
      raise "dry-run delete returned a different UID" unless deleted.dig("details", "uid") == created.dig("metadata", "uid")

      {"duplicate" => duplicate, "invalidOptions" => invalid, "delete" => deleted, "collection" => list}
    end

    def checked(response, expected)
      raise "expected HTTP #{expected}, received #{response.status}: #{response.body.to_s[0, 500]}" unless response.status == expected

      response.json
    end

    def check_events(events, cursor, name, created, updated)
      types = events.map { |event| event.fetch("type") }
      raise "unexpected watch event order #{types.inspect}" unless types == %w[ADDED MODIFIED DELETED]

      objects = events.map { |event| event.fetch("object") }
      uid = created.fetch("metadata").fetch("uid")
      unless !uid.empty? && objects.all? { |object| object.dig("metadata", "name") == name && object.dig("metadata", "uid") == uid }
        raise "watch events refer to different objects"
      end

      event_versions = objects.map { |object| object.fetch("metadata").fetch("resourceVersion") }
      revisions = [cursor, *event_versions].map { |version| Integer(version, 10) }
      raise "watch revisions must strictly increase" unless revisions.each_cons(2).all? { |before, after| before < after }

      write_versions = [created, updated].map { |object| object.fetch("metadata").fetch("resourceVersion") }
      raise "watch revisions differ from their write responses" unless event_versions.first(2) == write_versions
      raise "watch lost ConfigMap contents" unless objects.map { |object| object.dig("data", "message") } == %w[first second second]
    end
  end
end
