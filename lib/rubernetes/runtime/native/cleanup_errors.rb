# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # The bookkeeping of cleanup failures: one structured entry per resource
      # that could not be released, deduplicated and attached to the error the
      # caller sees so a retry knows what is still pending.
      module CleanupErrors
        private

        def cleanup_error_entry(resource:, error:, blocked_by: nil)
          entry = {
            "resource" => String(resource),
            "error" => reports_message?(error) ? "#{error.class}: #{error.message}" : String(error),
            "state" => "cleanup_pending"
          }
          entry["blocked_by"] = String(blocked_by) if blocked_by
          entry
        end

        def cleanup_error_details(cleanup_errors)
          Array(cleanup_errors).map do |entry|
            if mapping?(entry)
              entry.to_h.transform_keys(&:to_s)
            else
              resource, message = String(entry).split(": ", 2)
              {"resource" => resource, "error" => message || String(entry)}
            end
          end.map { |entry| immutable(entry) }.freeze
        end

        # The structured cleanup failures +error+ carries, or [] when it
        # carries none.
        def attached_cleanup_errors(error)
          carries_cleanup_errors?(error) && !error.cleanup_errors.empty? ? error.cleanup_errors : []
        end

        # Keep the original operation exception as the raised value while making
        # durable cleanup failures available to callers that need to retry them.
        # Native callers historically receive the primary exception directly, so
        # wrapping it would obscure the actual effect-point failure.
        def preserve_cleanup_errors(error, cleanup_errors)
          existing = carries_cleanup_errors?(error) ? Array(error.cleanup_errors) : []
          details = dedupe_cleanup_errors(existing + cleanup_error_details(cleanup_errors))
          return error if details.empty?

          if carries_cleanup_errors?(error)
            error.instance_variable_set(:@cleanup_errors, details.freeze)
          else
            error.instance_variable_set(:@native_cleanup_errors, details.freeze)
            error.define_singleton_method(:cleanup_errors) { @native_cleanup_errors }
          end
          error
        rescue StandardError
          # Exception objects may be frozen or reject singleton methods. The
          # structured rollback event remains the durable source of truth.
          error
        end

        def dedupe_cleanup_errors(entries)
          seen = {}
          Array(entries).each_with_object([]) do |entry, result|
            key = cleanup_error_key(entry)
            next if seen[key]

            seen[key] = true
            result << entry
          end
        end

        def cleanup_error_key(entry)
          value = if mapping?(entry)
                    entry.to_h
                  elsif reports_message?(entry)
                    {"class" => entry.class.name.to_s, "message" => entry.message.to_s}
                  else
                    entry
                  end
          canonical_cleanup_value(value)
        end

        def canonical_cleanup_value(value)
          case value
          when Hash
            value.keys.map(&:to_s).sort.map do |key|
              child = if value.key?(key)
                        value[key]
                      elsif value.key?(key.to_sym)
                        value[key.to_sym]
                      end
              [key, canonical_cleanup_value(child)]
            end
          when Array
            value.map { |child| canonical_cleanup_value(child) }
          else
            [value.class.name.to_s, value]
          end
        end
      end
    end
  end
end
