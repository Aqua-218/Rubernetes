# frozen_string_literal: true

require_relative "../codec"

module Rubernetes
  module Schema
    class Codec
      # The Kubernetes profile uses byte strings for Go strings and prefixes
      # each serialized object, including each watch event, with tag 55799.
      module KubernetesCBOR
        CONTENT_TYPE = "application/cbor"
        WATCH_CONTENT_TYPE = "application/cbor-seq"
        APPLY_CONTENT_TYPE = "application/apply-patch+cbor"
        PREFIX = "\xd9\xd9\xf7".b.freeze

        module_function

        def encode(object, deterministic: true, max_bytes: Codec::DEFAULT_MAX_BYTES)
          PREFIX + CBOR.encode(object, canonical: deterministic, kubernetes: true, max_bytes: max_bytes - PREFIX.bytesize)
        end

        def decode(bytes, max_bytes: Codec::DEFAULT_MAX_BYTES)
          CBOR.decode(bytes, strict: false, kubernetes: true, max_bytes: max_bytes)
        end
      end
    end
  end
end
