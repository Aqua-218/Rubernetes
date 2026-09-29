# frozen_string_literal: true

module M0SourceInventory
  EXCLUSION_PATTERN = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/}.freeze

  module_function

  def excluded?(relative_path)
    relative_path.empty? || relative_path.match?(EXCLUSION_PATTERN)
  end
end
