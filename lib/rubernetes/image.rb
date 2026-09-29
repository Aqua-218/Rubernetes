# frozen_string_literal: true

# Public OCI image subsystem entry point. Every implementation file is kept
# under image/ so node/runtime callers can require one stable facade.
require_relative "image/errors"
require_relative "image/strict_json"
require_relative "image/media_types"
require_relative "image/digest"
require_relative "image/reference"
require_relative "image/manifest"
require_relative "image/content_store"
require_relative "image/layer_extractor"
require_relative "image/registry_client"
require_relative "image/puller"
require_relative "image/resolver"
require_relative "image/verifier"
