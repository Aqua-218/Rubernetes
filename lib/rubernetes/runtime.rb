# frozen_string_literal: true

# Public runtime contract.  Backend-specific code depends on these common
# lifecycle, ownership, durability, and reconciliation primitives.
require_relative "runtime/common/errors"
require_relative "runtime/common/canonical"
require_relative "runtime/common/strict_json"
require_relative "runtime/common/state_machine"
require_relative "runtime/common/wal"
require_relative "runtime/common/snapshot"
require_relative "runtime/common/ownership"
require_relative "runtime/common/rollback"
require_relative "runtime/common/recovery"
require_relative "runtime/common/manager"
