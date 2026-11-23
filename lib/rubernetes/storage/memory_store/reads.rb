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
        shard_selector: nil,
        stats: nil,
        token_time: nil,
        **options
      )
        resource_version = options.delete(:at_revision) if options.key?(:at_revision)
        continue ||= continue_token || options.delete(:token)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown list options: #{options.keys.join(", ")}" unless options.empty?

        normalized_prefix = String(prefix || "")
        normalized_limit = normalize_limit(limit)
        normalized_resource_version_match = normalize_resource_version_match(resource_version_match)
        selector_object = build_selector(selector, label_selector, field_selector, shard: shard_selector)

        @monitor.synchronize do
          token_time ||= clock_value if continue || normalized_limit
          token = decode_continue_token(continue) if continue
          if token
            normalized_resource_version_match ||= token["resource_version_match"]
            validate_continue_token!(token, normalized_prefix, selector_object, normalized_resource_version_match)
            expire_continue!(token, token_time)
            snapshot_revision = token["latest"] == true && @token_secret ? @revision : token.fetch("revision")
            list_page_locked(normalized_prefix, selector_object, snapshot_revision, normalized_limit,
                             token.fetch("last_key"), normalized_resource_version_match, stats, expires_at: token["expires_at"])
          else
            snapshot_revision = resolve_list_revision(resource_version, normalized_resource_version_match,
                                                      limit: normalized_limit)
            list_page_locked(normalized_prefix, selector_object, snapshot_revision, normalized_limit, nil,
                             normalized_resource_version_match, stats, expires_at: (token_time + LIST_CONTINUE_SECONDS if normalized_limit))
          end
        end
      end

      private

      # One page of the snapshot at +snapshot_revision+, starting after +last_key+.
      def list_page_locked(prefix, selector_object, snapshot_revision, effective_limit, last_key, resource_version_match, stats, expires_at:)
        ensure_snapshot_available!(snapshot_revision)
        # If every indexed key is live, the width of the prefix range gives
        # its count without reading objects beyond the page. Historical lists
        # and retained deletions still need MVCC lookups for that count.
        keys = sorted_keys_locked
        range = prefix_range(keys, prefix, last_key)
        live_count = range.size if snapshot_revision == @revision && @deleted_versions.empty?
        selected = []
        fetched = 0
        more = false
        last_selected_key = nil
        filtered = selector_object.filters_attributes?
        range.each do |index|
          key = keys[index]
          object = object_at_revision(key, snapshot_revision)
          next unless object

          fetched += 1
          next if more

          full = effective_limit && selected.length >= effective_limit
          # Sharded pages resume after the last returned key even when all
          # subsequent keys belong to another shard.
          next unless (full && selector_object.shard) || selector_object.matches?(object)

          if full
            more = true
            break if live_count || (filtered && !selector_object.shard)
          else
            selected << object
            last_selected_key = key
          end
        end
        fetched = live_count if more && live_count && (!filtered || selector_object.shard)
        if stats
          stats[:fetched] = fetched
          stats[:returned] = selected.length
        end
        ListResult.new(
          items: selected,
          resource_version: snapshot_revision,
          continue_token: (if more && last_selected_key
                             encode_continue_token(
                               "revision" => snapshot_revision, "prefix" => prefix, "selector" => selector_object.signature,
                               "limit" => effective_limit, "resource_version_match" => resource_version_match,
                               "last_key" => last_selected_key, "expires_at" => expires_at
                             )
                           end),
          remaining_item_count: (fetched - selected.length if more && !filtered)
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
        exact = resource_version_match == "Exact" || (resource_version_match.nil? && limit)
        return resolve_read_revision(resource_version) if exact
        return @revision if resource_version.nil? || resource_version == ""

        requested = parse_revision(resource_version)
        raise InvalidResourceVersion, "resourceVersion #{requested} is ahead of current revision #{@revision}" if requested > @revision

        @revision
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
        # Older Raft replicas understand the outer envelope and its integer
        # revision. Upgraded readers also verify the deadline and cursor
        # against a per-cluster key before serving the pinned snapshot.
        if @token_secret
          body["signed_revision"] = body.fetch("revision")
          body["authenticator"] = continue_authenticator(body)
        else
          body.delete("expires_at")
          body.delete("latest")
        end
        body["signature"] = legacy_continue_signature(body)
        MemoryStoreSupport.base64_url_encode(JSON.generate(body))
      end

      def continue_authenticator(payload)
        OpenSSL::HMAC.hexdigest("SHA256", @token_secret, MemoryStoreSupport.canonical_json(payload))
      end

      def legacy_continue_signature(payload)
        MemoryStoreSupport.digest(payload.merge("secret" => @legacy_token_secret))
      end

      def decode_continue_token(token)
        encoded = String(token)
        decoded = MemoryStoreSupport.base64_url_decode(encoded)
        payload = JSON.parse(decoded)
        raise InvalidContinueToken unless payload.is_a?(Hash) && payload["version"] == 1

        signature = payload.delete("signature")
        expected = legacy_continue_signature(payload)
        raise InvalidContinueToken unless signature.is_a?(String) && OpenSSL.fixed_length_secure_compare(signature, expected)

        if @token_secret && payload.key?("authenticator")
          authenticator = payload.fetch("authenticator")
          # Legacy compaction recovery re-encodes the cursor with a new
          # outer revision. Authenticate the original revision, then give
          # that recovery token a new deadline via expire_continue!.
          original = payload.except("authenticator").merge("revision" => payload["signed_revision"])
          expected = continue_authenticator(original)
          raise InvalidContinueToken unless authenticator.is_a?(String) && OpenSSL.fixed_length_secure_compare(authenticator, expected)
        end
        payload
      rescue ArgumentError, JSON::ParserError, TypeError
        raise InvalidContinueToken
      end

      def validate_continue_token!(token, prefix, selector, resource_version_match)
        raise InvalidContinueToken unless token["prefix"] == prefix && token["selector"] == selector.signature
        raise InvalidContinueToken unless token["resource_version_match"] == resource_version_match

        last_key = token["last_key"]
        raise InvalidContinueToken unless last_key.is_a?(String) && last_key.start_with?(prefix)

        revision = token["revision"]
        raise InvalidContinueToken unless revision.is_a?(Integer) && revision >= 0
        return unless @token_secret && token.key?("authenticator")

        expires_at = token["expires_at"]
        raise InvalidContinueToken unless expires_at.is_a?(Numeric) && expires_at.finite?
      end

      def expire_continue!(token, now)
        revision = token["revision"]
        timed = @token_secret && token.key?("authenticator")
        compacted = !(timed && token["latest"] == true) && revision < @compacted_revision
        # Legacy tokens have no issuance time. Offer the same recovery as a
        # timed-out token once this replica has the replicated signing key.
        expired = @token_secret && (!timed || revision != token["signed_revision"] || now >= token.fetch("expires_at"))
        return unless compacted || expired

        # The client may restart from the beginning for consistency, or
        # resume at the same key against the newest snapshot at retry time.
        cursor = token.slice("prefix", "selector", "resource_version_match", "last_key")
        inconsistent = encode_continue_token(cursor.merge("revision" => @revision, "latest" => true,
                                                          "expires_at" => now + LIST_CONTINUE_SECONDS))
        raise Gone.new(revision, (@compacted_revision if compacted), continue_token: inconsistent)
      end
    end
  end
end
