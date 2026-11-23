# frozen_string_literal: true

require "json"

require_relative "../../lib/rubernetes/client"

module Conformance
  class K5ListWatch
    CONFIG_MAPS = "/api/v1/namespaces/default/configmaps"
    LABEL = "k5.rubernetes.io/fixture"
    JSON_TYPE = "application/json"
    INITIAL_NAMES = %w[a b c d e].freeze

    class Error < StandardError; end

    def self.observables
      [{"id" => "configmap_list_continue_snapshot", "list_watch" => :snapshot},
       {"id" => "configmap_list_watch_causality", "list_watch" => :handoff}]
    end

    def self.run(mode, kubeconfig, fixture)
      context = Rubernetes::Client::Kubeconfig.load(kubeconfig).resolve
      client = Rubernetes::Client::HTTPClient.new(context: context, read_timeout: 15)
      new(client, "#{fixture}-#{mode}").run(mode)
    ensure
      client&.close
    end

    def initialize(client, fixture)
      @client = client
      @fixture = fixture
      @selector = {"labelSelector" => "#{LABEL}=#{fixture}"}
      @created = {}
      @trace = []
    end

    def run(mode)
      result = observe(mode)
      failures = cleanup
      result["exit_status"] = 1 unless failures.empty?
      result.merge("stderr" => [result.fetch("stderr"), *failures].reject(&:empty?).join("\n"), "trace" => @trace)
    end

    private

    def observe(mode)
      originals = INITIAL_NAMES.map { |name| create(name, "initial-#{name}") }
      ids = originals.map { |item| item.dig("metadata", "uid") }
      unless ids.all? { |uid| uid.is_a?(String) && uid.match?(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/) } && ids.uniq == ids
        raise Error, "fixture objects must have distinct UUIDs"
      end

      summary = mode == :snapshot ? snapshot(originals) : handoff(originals)
      {"exit_status" => 0, "stdout" => JSON.generate(summary), "stderr" => ""}
    rescue Error, Rubernetes::Client::Error, JSON::ParserError, KeyError => error
      {"exit_status" => 1, "stdout" => "", "stderr" => error.message}
    end

    def snapshot(originals)
      updated = nil
      added = nil
      pages = paginated(originals) do
        updated = patch("d", "updated-d")
        added = create("cc", "added-cc")
      end
      cursor = version(pages.last)
      require_increasing(cursor, version(updated), version(added))
      exact = historical(cursor)
      expect_items(exact.fetch("items"), originals, "Exact LIST snapshot")
      raise Error, "Exact LIST returned a different resourceVersion" unless version(exact) == cursor

      current = selected_list("resourceVersion" => version(added).to_s, "resourceVersionMatch" => "NotOlderThan")
      expect_items(current.fetch("items"), [*originals.first(3), added, updated, originals.last], "NotOlderThan LIST")
      raise Error, "NotOlderThan LIST is older than its write" if version(current) < version(added)

      check_unfiltered_remaining_count
      {"pages" => pages.map { |page| values(page.fetch("items")) }, "exact" => values(exact.fetch("items")),
       "notOlderThan" => values(current.fetch("items")), "unfilteredRemainingCountAccurate" => true}
    end

    def handoff(originals)
      updated = nil
      pages = paginated(originals) { updated = patch("d", "updated-d") }
      added = create("cc", "added-cc")
      cursor = version(pages.last)
      require_increasing(cursor, version(updated), version(added))
      events = watch(cursor)
      types = events.map { |event| event.fetch("type") }
      raise Error, "WATCH from continued LIST returned #{types.inspect}" unless types == %w[MODIFIED ADDED]

      expect_items(events.map { |event| event.fetch("object") }, [updated, added], "WATCH write identities")
      exact_updates = events.map { |event| historical(version(event.fetch("object"))) }
      expect_items(exact_updates.first.fetch("items"), [*originals.first(3), updated, originals.last], "LIST at MODIFIED")
      expect_items(exact_updates.last.fetch("items"), [*originals.first(3), added, updated, originals.last], "LIST at ADDED")
      unless exact_updates.map { |list| version(list) } == [version(updated), version(added)]
        raise Error, "Exact LIST resourceVersions do not match the WATCH events"
      end

      {"events" => events.map { |event| [event.fetch("type"), *values([event.fetch("object")]).first] },
       "exactAtEvent" => exact_updates.map { |list| values(list.fetch("items")) }}
    end

    def paginated(originals)
      query = {"limit" => "2"}
      first = selected_list(query)
      raise Error, "first page omits a completed write" if version(first) < originals.map { |item| version(item) }.max

      yield
      pages = [first]
      tokens = []
      2.times do
        token = pages.last.dig("metadata", "continue")
        raise Error, "page must have a new opaque continue token" unless token.is_a?(String) && !token.empty? && !tokens.include?(token)

        tokens << token
        pages << selected_list(query.merge("continue" => token))
      end
      unless pages.all? { |page| version(page) == version(first) } && pages.last.dig("metadata", "continue").to_s.empty?
        raise Error, "continued pages must share one snapshot and finish without a token"
      end

      pages.zip(originals.each_slice(2)).each { |page, expected| expect_items(page.fetch("items"), expected, "continued LIST") }
      raise Error, "filtered LIST unexpectedly reported remainingItemCount" if pages.any? { |page| page.fetch("metadata").key?("remainingItemCount") }

      pages
    end

    def check_unfiltered_remaining_count
      full = list
      page = list("limit" => "2", "resourceVersion" => version(full).to_s, "resourceVersionMatch" => "Exact")
      expected = full.fetch("items").length - 2
      observed = page.dig("metadata", "remainingItemCount")
      return if observed == expected && page.fetch("items").length == 2 && version(page) == version(full)

      raise Error, "unfiltered Exact LIST remainingItemCount #{observed.inspect}, expected #{expected}"
    end

    def selected_list(query)
      list(@selector.merge(query))
    end

    def historical(cursor)
      selected_list("resourceVersion" => cursor.to_s, "resourceVersionMatch" => "Exact")
    end

    def list(query = {})
      response = request("GET", CONFIG_MAPS, 200, query: query)
      unless response.values_at("apiVersion", "kind") == %w[v1 ConfigMapList] && response["items"].is_a?(Array)
        raise Error, "GET returned an unexpected ConfigMapList"
      end

      response
    end

    def watch(cursor)
      query = @selector.merge("watch" => "true", "resourceVersion" => cursor.to_s, "timeoutSeconds" => "3")
      response = @client.request("GET", CONFIG_MAPS, query: query)
      record = record_exchange("GET", CONFIG_MAPS, query, response)
      verify_response(response, 200)
      events = response.body.lines.reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }
      record["events"] = events.map { |event| [event["type"], trace_item(event.fetch("object"))] }
      events
    end

    def create(name, value)
      object = {"apiVersion" => "v1", "kind" => "ConfigMap", "data" => {"value" => value},
                "metadata" => {"name" => "#{@fixture}-#{name}", "labels" => {LABEL => @fixture}}}
      created = request("POST", CONFIG_MAPS, 201, body: object)
      @created[name] = created.fetch("metadata").fetch("uid")
      created
    end

    def patch(name, value)
      request("PATCH", "#{CONFIG_MAPS}/#{@fixture}-#{name}", 200,
              body: {"data" => {"value" => value}}, headers: {"Content-Type" => "application/merge-patch+json"})
    end

    def cleanup
      @created.filter_map do |name, uid|
        path = "#{CONFIG_MAPS}/#{@fixture}-#{name}"
        request("DELETE", path, 200, body: {"preconditions" => {"uid" => uid}})
        request("GET", path, 404)
        nil
      rescue Error, Rubernetes::Client::Error, JSON::ParserError => error
        "cleanup #{name}: #{error.message}"
      end
    end

    def request(method, path, expected, query: {}, body: nil, headers: {})
      response = @client.request(method, path, query: query, body: body, headers: headers)
      record = record_exchange(method, path, query, response)
      record["requestBody"] = body if body
      content = response.json
      raise Error, "#{method} did not return a JSON object" unless content.is_a?(Hash)

      record["body"] = trace_body(content)
      verify_response(response, expected)
      content
    end

    def record_exchange(method, path, query, response)
      record = {"method" => method, "path" => path, "query" => query, "status" => response.status,
                "contentType" => response["content-type"]}
      @trace << record
      record
    end

    def trace_body(content)
      return content.slice("kind", "reason", "details", "message") if content["kind"] == "Status"
      return trace_item(content) unless content["items"]

      {"metadata" => content.fetch("metadata"), "itemCount" => content.fetch("items").size,
       "fixtureItems" => content.fetch("items").select { |item| item.dig("metadata", "labels", LABEL) == @fixture }.map { |item| trace_item(item) }}
    end

    def trace_item(item)
      {"name" => item.dig("metadata", "name"), "uid" => item.dig("metadata", "uid"),
       "resourceVersion" => item.dig("metadata", "resourceVersion"), "value" => item.dig("data", "value")}
    end

    def verify_response(response, expected)
      media_type = response["content-type"].to_s.split(";", 2).first
      return if response.status == expected && media_type == JSON_TYPE

      raise Error, "expected HTTP #{expected} #{JSON_TYPE}, got #{response.status} #{media_type.inspect}"
    end

    def expect_items(actual, expected, operation)
      return if actual.map { |item| trace_item(item) } == expected.map { |item| trace_item(item) }

      raise Error, "#{operation} returned different names, values, UIDs or resourceVersions"
    end

    def values(items)
      items.map { |item| [item.dig("metadata", "name").delete_prefix("#{@fixture}-"), item.dig("data", "value")] }
    end

    def version(object)
      text = object.dig("metadata", "resourceVersion")
      raise Error, "invalid positive resourceVersion #{text.inspect}" unless text.is_a?(String) && text.match?(/\A[1-9][0-9]*\z/)

      Integer(text, 10)
    end

    def require_increasing(*versions)
      raise Error, "resourceVersions must strictly increase" unless versions.each_cons(2).all? { |before, after| before < after }
    end
  end
end
