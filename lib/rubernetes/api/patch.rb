# frozen_string_literal: true

require "time"

module Rubernetes
  module API
    # RFC 6902, RFC 7386 and strategic merge patches (server-side apply is
    # ManagedFields::FieldManager).
    module Patch
      CONTENT_TYPES = {
        "application/json-patch+json" => :json,
        "application/merge-patch+json" => :merge,
        "application/strategic-merge-patch+json" => :strategic,
        "application/apply-patch+yaml" => :apply,
        "application/apply-patch+cbor" => :apply_cbor
      }.freeze

      class Error < Status::Invalid; end

      module_function

      def type_for(content_type)
        CONTENT_TYPES[content_type.to_s.split(";", 2).first]
      end

      def apply(object, patch, type:, resource: nil)
        case type.to_sym
        when :json, :json_patch
          apply_json_patch(object, patch)
        when :merge, :merge_patch
          apply_merge_patch(object, patch)
        when :strategic, :strategic_merge
          apply_strategic_merge(object, patch, resource: resource)
        else
          raise Error, "unsupported patch type #{type.inspect}"
        end
      end

      def apply_json_patch(object, operations)
        operations = deep_copy(operations)
        raise Error, "JSON Patch body must be an array of operations" unless operations.is_a?(Array)

        result = deep_copy(object)
        operations.each_with_index do |operation, index|
          raise Error, "JSON Patch operation #{index} must be an object" unless operation.is_a?(Hash)

          op = value_for(operation, "op").to_s.downcase
          path = value_for(operation, "path")
          raise Error, "JSON Patch operation #{index} is missing path" if path.nil?

          case op
          when "add"
            result = pointer_add(result, path, value_for(operation, "value"))
          when "remove"
            result = pointer_remove(result, path)
          when "replace"
            pointer_get(result, path)
            result = pointer_replace(result, path, value_for(operation, "value"))
          when "move"
            from = value_for(operation, "from")
            raise Error, "JSON Patch move operation #{index} is missing from" if from.nil?
            raise Error, "JSON Patch move operation #{index} cannot move a value into its own descendant" if pointer_descendant?(from, path)

            value = pointer_get(result, from)
            result = pointer_remove(result, from)
            result = pointer_add(result, path, value)
          when "copy"
            from = value_for(operation, "from")
            raise Error, "JSON Patch copy operation #{index} is missing from" if from.nil?

            result = pointer_add(result, path, pointer_get(result, from))
          when "test"
            expected = value_for(operation, "value")
            actual = pointer_get(result, path)
            raise Error, "JSON Patch test failed at #{path.inspect}" unless deep_equal?(actual, expected)
          else
            raise Error, "JSON Patch operation #{index} has unsupported op #{op.inspect}"
          end
        rescue KeyError => error
          raise Error, "JSON Patch operation #{index} is invalid: #{error.message}"
        end
        result
      end

      def apply_merge_patch(object, patch)
        return deep_copy(patch) unless patch.is_a?(Hash)

        target = object.is_a?(Hash) ? deep_copy(object) : {}
        patch.each do |raw_key, value|
          key = raw_key.to_s
          if value.nil?
            target.delete(key)
            target.delete(raw_key) unless raw_key == key
          elsif value.is_a?(Hash)
            target[key] = apply_merge_patch(target[key], value)
          else
            target[key] = deep_copy(value)
          end
        end
        target
      end

      def apply_strategic_merge(object, patch, resource: nil)
        raise Error, "strategic merge patch body must be an object" unless patch.is_a?(Hash)

        merge_keys = resource.respond_to?(:merge_keys) ? resource.merge_keys : {}
        strategic_merge(deep_copy(object), patch, path: [], merge_keys: merge_keys)
      end

      def strategic_merge(base, patch, path:, merge_keys:)
        return deep_copy(patch) unless patch.is_a?(Hash)

        directive = patch["$patch"] || patch[:$patch]
        raise Error, "unsupported strategic merge directive #{directive.inspect}" if directive && !%w[replace].include?(directive.to_s)

        retain_keys = patch["$retainKeys"] || patch[:$retainKeys]
        raise Error, "$retainKeys must be an array" if (patch.key?("$retainKeys") || patch.key?(:$retainKeys)) && !retain_keys.is_a?(Array)
        return deep_copy(patch.reject { |key, _| key.to_s == "$patch" }) if directive.to_s == "replace"
        return deep_copy(patch) unless base.is_a?(Hash)

        if retain_keys.is_a?(Array)
          retained = retain_keys.map(&:to_s)
          base = base.select { |key, _| retained.include?(key.to_s) }
        end

        patch.each_with_object(base) do |(raw_key, patch_value), result|
          key = raw_key.to_s
          next if key == "$patch" || key == "$retainKeys" || key.start_with?("$setElementOrder/")

          if patch_value.nil?
            result.delete(key)
            next
          end
          current = result[key]
          result[key] = if patch_value.is_a?(Hash)
                          strategic_merge(current, patch_value, path: path + [key], merge_keys: merge_keys)
                        elsif patch_value.is_a?(Array)
                          strategic_merge_array(current, patch_value, path: path + [key], merge_keys: merge_keys,
                                                                      order: patch["$setElementOrder/#{key}"])
                        else
                          deep_copy(patch_value)
                        end
        end
      end

      def strategic_merge_array(current, patch, path:, merge_keys:, order: nil)
        merge_key = merge_key_for(path, merge_keys)
        return deep_copy(patch) if merge_key.nil? || !current.is_a?(Array)

        merged = merge_keyed_items(current, patch, path: path, merge_key: merge_key, merge_keys: merge_keys)
        order_merged_items(merged, current, order.is_a?(Array) ? order : patch, merge_key)
      end

      # strategicpatch.normalizeElementOrder: the items the patch names come
      # in the patch's (or $setElementOrder's) order, and the items only the
      # server had are slotted in among them by their live order.  Appending
      # new items at the end instead made a patch that renames a pod
      # template's only container leave the OLD container first, so
      # "[sig-apps] ReplicaSet Replace and Patch tests" never saw its image.
      def order_merged_items(merged, current, order, merge_key)
        identity = ->(item) { item.is_a?(Hash) ? item[merge_key].to_s : item }
        order_index = order.each_with_index.to_h { |item, index| [identity.call(item), index] }
        server_index = current.each_with_index.to_h { |item, index| [identity.call(item), index] }
        patch_items, server_only = merged.partition { |item| order_index.key?(identity.call(item)) }
        patch_items = patch_items.each_with_index.sort_by { |item, index| [order_index[identity.call(item)], index] }.map(&:first)
        result = []
        until server_only.empty? && patch_items.empty?
          if patch_items.empty?
            result << server_only.shift
          elsif server_only.empty?
            result << patch_items.shift
          else
            left = server_index[identity.call(server_only.first)]
            right = server_index[identity.call(patch_items.first)]
            result << (left && right && left < right ? server_only.shift : patch_items.shift)
          end
        end
        result
      end

      def merge_keyed_items(current, patch, path:, merge_key:, merge_keys:)
        result = deep_copy(current)
        patch.each do |item|
          if item.is_a?(Hash) && item.key?("$patch") && !%w[delete replace].include?(item["$patch"].to_s)
            raise Error, "unsupported strategic merge directive #{item["$patch"].inspect}"
          end

          if item.is_a?(Hash) && item.key?(merge_key)
            existing_index = result.index { |candidate| candidate.is_a?(Hash) && candidate[merge_key].to_s == item[merge_key].to_s }
            if item["$patch"] == "delete"
              result.delete_at(existing_index) if existing_index
            elsif existing_index
              result[existing_index] =
                strategic_merge(result[existing_index], item, path: path + ["#{merge_key}=#{item[merge_key]}"], merge_keys: merge_keys)
            else
              result << deep_copy(item.reject { |key, _| key.to_s == "$patch" })
            end
          else
            result << deep_copy(item) unless result.any? { |candidate| deep_equal?(candidate, item) }
          end
        end
        result
      end

      def merge_key_for(path, merge_keys)
        path_string = path.join(".")
        return merge_keys[path_string].to_s unless merge_keys[path_string].nil?
        return merge_keys[path.join("/")].to_s unless merge_keys[path.join("/")].nil?

        normalized_path = path.reject { |part| part.to_s.include?("=") }
        normalized_string = normalized_path.join(".")
        return merge_keys[normalized_string].to_s unless merge_keys[normalized_string].nil?

        merge_keys.each do |pattern, key|
          pattern_path = pattern.to_s.gsub("[*]", "").split(".").reject(&:empty?)
          return key.to_s if pattern_path == normalized_path
        end
        return "name" if %w[containers env].include?(path.last.to_s)

        nil
      end

      def pointer_get(document, pointer)
        return document if pointer.to_s.empty?

        tokens = pointer_tokens(pointer)
        tokens.reduce(document) { |value, token| read_token(value, token) }
      end

      def pointer_add(document, pointer, value)
        return deep_copy(value) if pointer.to_s.empty?

        parent, token = pointer_parent(document, pointer)
        if parent.is_a?(Array)
          index = token == "-" ? parent.length : array_index(token, parent.length, allow_end: true)
          parent.insert(index, deep_copy(value))
        elsif parent.is_a?(Hash)
          parent[token] = deep_copy(value)
        else
          raise Error, "JSON Pointer parent #{pointer.inspect} is not a container"
        end
        document
      end

      def pointer_replace(document, pointer, value)
        return deep_copy(value) if pointer.to_s.empty?

        parent, token = pointer_parent(document, pointer)
        if parent.is_a?(Array)
          index = array_index(token, parent.length)
          parent[index] = deep_copy(value)
        elsif parent.is_a?(Hash)
          raise Error, "JSON Pointer path #{pointer.inspect} does not exist" unless parent.key?(token)

          parent[token] = deep_copy(value)
        else
          raise Error, "JSON Pointer parent #{pointer.inspect} is not a container"
        end
        document
      end

      def pointer_remove(document, pointer)
        return nil if pointer.to_s.empty?

        parent, token = pointer_parent(document, pointer)
        if parent.is_a?(Array)
          parent.delete_at(array_index(token, parent.length))
        elsif parent.is_a?(Hash)
          raise Error, "JSON Pointer path #{pointer.inspect} does not exist" unless parent.key?(token)

          parent.delete(token)
        else
          raise Error, "JSON Pointer parent #{pointer.inspect} is not a container"
        end
        document
      end

      def pointer_parent(document, pointer)
        tokens = pointer_tokens(pointer)
        raise Error, "JSON Pointer must begin with /" if tokens.empty?

        parent = tokens[0...-1].reduce(document) { |value, token| read_token(value, token) }
        [parent, tokens.last]
      end

      def pointer_tokens(pointer)
        value = pointer.to_s
        raise Error, "JSON Pointer must begin with /" unless value.empty? || value.start_with?("/")

        value.split("/", -1)[1..].to_a.map do |token|
          raise Error, "JSON Pointer token #{token.inspect} has an invalid escape" if token.match?(/~(?![01])/)

          token.gsub("~1", "/").gsub("~0", "~")
        end
      end

      def pointer_descendant?(from, path)
        from_tokens = pointer_tokens(from)
        path_tokens = pointer_tokens(path)
        return false if from_tokens.empty? || path_tokens.length <= from_tokens.length

        path_tokens.first(from_tokens.length) == from_tokens
      end

      def read_token(value, token)
        if value.is_a?(Array)
          value.fetch(array_index(token, value.length))
        elsif value.is_a?(Hash)
          raise Error, "JSON Pointer path token #{token.inspect} does not exist" unless value.key?(token)

          value.fetch(token)
        else
          raise Error, "JSON Pointer token #{token.inspect} traverses a scalar"
        end
      end

      def array_index(token, size, allow_end: false)
        raise Error, "JSON Pointer array index #{token.inspect} is invalid" unless token.to_s == "0" || token.to_s.match?(/\A[1-9][0-9]*\z/)

        index = Integer(token, 10)
        max = allow_end ? size : size - 1
        raise Error, "JSON Pointer array index #{token.inspect} is out of range" if index.negative? || index > max

        index
      rescue ArgumentError
        raise Error, "JSON Pointer array index #{token.inspect} is invalid"
      end

      def value_for(hash, key)
        return hash[key] if hash.key?(key)
        return hash[key.to_sym] if hash.key?(key.to_sym)

        raise KeyError, "missing #{key}"
      end

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
        when Array
          value.map { |item| deep_copy(item) }
        else
          value
        end
      end

      def deep_equal?(left, right)
        left == right
      end
    end
  end
end
