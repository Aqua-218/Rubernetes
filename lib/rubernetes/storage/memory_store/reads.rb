# frozen_string_literal: true

module Rubernetes
  module Storage
    # get and list, with the continue tokens that page a list over one snapshot.
    class MemoryStore
      def get(key, out: nil, resource_version: nil, **options)
        resource_version = options.delete(:at_revision) if options.key?(:at_revision)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown get options: #{options.keys.join(", ")}" unless options.empty?

        normalized_key = normalize_key(key)
        @monitor.synchronize do
          snapshot_revision = resolve_read_revision(resource_version)
          object = object_at_revision(normalized_key, snapshot_revision)
          raise NotFound, normalized_key if object.nil?

          response = MemoryStoreSupport.immutable_copy(object)
          copy_to_out(out, response) if out
          response
        end
      end

      # Returns a tuple-compatible ListResult. Continue tokens pin a snapshot
      # revision, preventing mutations between pages from causing gaps/duplicates.
      def list(
        prefix = "",
        selector: nil,
        label_selector: nil,
        field_selector: nil,
        limit: nil,
        continue: nil,
        continue_token: nil,
        resource_version: nil,
        resource_version_match: nil,
        stats: nil,
        **options
      )
        resource_version = options.delete(:at_revision) if options.key?(:at_revision)
        continue ||= continue_token || options.delete(:token)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown list options: #{options.keys.join(", ")}" unless options.empty?

        normalized_prefix = String(prefix || "")
        normalized_limit = normalize_limit(limit)
        normalized_resource_version_match = normalize_resource_version_match(resource_version_match)
        selector_object = build_selector(selector, label_selector, field_selector)

        @monitor.synchronize do
          token = decode_continue_token(continue) if continue
          if token
            normalized_resource_version_match ||= token["resource_version_match"]
            validate_continue_token!(token, normalized_prefix, selector_object, normalized_limit,
                                     normalized_resource_version_match)
            token = restart_compacted_continue(token)
            list_page_locked(normalized_prefix, selector_object, token.fetch("revision"), token.fetch("limit"),
                             token.fetch("last_key"), normalized_resource_version_match, stats)
          else
            snapshot_revision = resolve_list_revision(resource_version, normalized_resource_version_match,
                                                      limit: normalized_limit)
            list_page_locked(normalized_prefix, selector_object, snapshot_revision, normalized_limit, nil,
                             normalized_resource_version_match, stats)
          end
        end
      end

      private

      # One page of the snapshot at +snapshot_revision+, starting after +last_key+.
      def list_page_locked(prefix, selector_object, snapshot_revision, effective_limit, last_key, resource_version_match, stats)
        ensure_snapshot_available!(snapshot_revision)
        # One pass.  This used to resolve every key in the prefix to its
        # object at the snapshot revision, keep them all, and then -- to
        # find the key the next page starts after -- resolve every key
        # again.  A paged walk of N objects therefore cost O(N) resolutions
        # per page and O(N^2) over the walk, which is why listing a
        # thousand objects a hundred at a time took minutes.  Without a
        # selector the scan stops one object past the page; with one it
        # must go on, because remainingItemCount counts the matches behind
        # the page and only a selector can hide them.
        selected = []
        last_selected_key = nil
        more = false
        extra_matches = 0
        fetched = 0
        keys_with_prefix_locked(prefix, after: last_key).each do |key|
          object = object_at_revision(key, snapshot_revision)
          next unless object

          fetched += 1
          next unless selector_object.matches?(object)

          if effective_limit && selected.length >= effective_limit
            more = true
            break if selector_object.empty?

            extra_matches += 1
            next
          end
          selected << object
          last_selected_key = key
        end
        # apiserver_cache_list_*: objects read from the cache to serve the
        # LIST, and objects returned.
        if stats
          stats[:fetched] = fetched
          stats[:returned] = selected.length
        end
        ListResult.new(
          items: selected.map { |object| MemoryStoreSupport.immutable_copy(object) },
          resource_version: snapshot_revision,
          continue_token: (if more && last_selected_key
                             encode_continue_token(
                               "revision" => snapshot_revision, "prefix" => prefix, "selector" => selector_object.signature,
                               "limit" => effective_limit, "resource_version_match" => resource_version_match,
                               "last_key" => last_selected_key
                             )
                           end),
          remaining_item_count: extra_matches.positive? && !selector_object.empty? ? extra_matches : nil
        )
      end

      def normalize_resource_version_match(value)
        return nil if value.nil? || value.to_s.empty?

        normalized = value.to_s
        return normalized if %w[Exact NotOlderThan].include?(normalized)

        raise InvalidResourceVersion, "resourceVersionMatch must be Exact or NotOlderThan"
      end

      def resolve_list_revision(resource_version, resource_version_match, limit: nil)
        # Kubernetes treats limit=0 as an unbounded list, while a resource
        # version still selects the snapshot used by the response. Exact
        # reads use that snapshot; NotOlderThan may use the latest revision.
        if resource_version_match == "NotOlderThan"
          requested = if resource_version.nil? || resource_version == "" || resource_version == 0 || resource_version == "0"
                        @revision
                      else
                        parse_revision(resource_version)
                      end
          raise InvalidResourceVersion, "resourceVersion #{requested} is ahead of current revision #{@revision}" if requested > @revision

          # NotOlderThan may safely serve the current revision even when the
          # requested lower bound has already been compacted.  Exact reads,
          # by contrast, must retain the requested snapshot and are rejected
          # by resolve_read_revision when it is gone.
          @revision
        elsif resource_version_match == "Exact" || (limit && limit.positive?)
          resolve_read_revision(resource_version)
        else
          # With no explicit match, the upstream cacher only honors an exact
          # RV for a chunked list.  An unchunked list uses the latest
          # consistent revision (including when the requested RV was compacted).
          unless resource_version.nil? || resource_version == "" || resource_version == 0 || resource_version == "0"
            requested = parse_revision(resource_version)
            raise InvalidResourceVersion, "resourceVersion #{requested} is ahead of current revision #{@revision}" if requested > @revision

          end
          @revision
        end
      end

      def copy_to_out(out, response)
        if out.is_a?(Hash)
          out.replace(MemoryStoreSupport.deep_dup(response))
          MemoryStoreSupport.deep_freeze(out)
        elsif Shape.callable?(out)
          out.call(response)
        else
          raise ArgumentError, "out must respond to replace or call"
        end
      end

      def normalize_limit(limit)
        return nil if limit.nil? || limit == ""

        value = Integer(limit)
        # ListOptions.limit=0 means no server-side limit, not an empty page.
        return nil if value.zero?
        raise ArgumentError, "limit must be positive" unless value.positive?

        value
      rescue TypeError, ArgumentError
        raise InvalidLimit, "limit must be a positive integer"
      end

      def encode_continue_token(payload)
        body = payload.merge("version" => 1)
        signed = body.merge("signature" => MemoryStoreSupport.digest(body.merge("secret" => @token_secret)))
        MemoryStoreSupport.base64_url_encode(JSON.generate(signed))
      end

      def decode_continue_token(token)
        encoded = String(token)
        decoded = MemoryStoreSupport.base64_url_decode(encoded)
        payload = JSON.parse(decoded)
        raise InvalidContinueToken unless payload.is_a?(Hash)

        signature = payload.delete("signature")
        expected = MemoryStoreSupport.digest(payload.merge("secret" => @token_secret))
        raise InvalidContinueToken unless signature == expected && payload["version"] == 1

        payload
      rescue ArgumentError, JSON::ParserError, TypeError
        raise InvalidContinueToken
      end

      def validate_continue_token!(token, prefix, selector, limit, resource_version_match)
        raise InvalidContinueToken unless token["prefix"] == prefix && token["selector"] == selector.signature
        raise InvalidContinueToken unless token["limit"] == limit
        raise InvalidContinueToken unless token["resource_version_match"] == resource_version_match
        raise InvalidContinueToken unless token["revision"].is_a?(Integer) && token["last_key"].is_a?(String)
      end

      # kube-apiserver answers a continue token whose snapshot has been
      # compacted away with 410 and hands back an "inconsistent" token: the
      # same position, resumed against the current snapshot.  A client given
      # no such token starts the listing over and re-reads every page it
      # already had, so a chunked listing returns more objects than exist.
      def restart_compacted_continue(token)
        revision = token.fetch("revision")
        return token if revision >= @compacted_revision

        inconsistent = encode_continue_token(token.merge("revision" => @revision))
        error = Gone.new(revision, @compacted_revision)
        error.details["continue"] = inconsistent
        raise error
      end
    end
  end
end
