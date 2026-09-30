# frozen_string_literal: true

module M0SourceInventory
  # apps/<app>/{log,tmp,storage}: an application's runtime artifacts (the
  # dashboard's development.log is written while gates run) are not source.
  EXCLUSION_PATTERN = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}

  module_function

  def excluded?(relative_path)
    relative_path.empty? || relative_path.match?(EXCLUSION_PATTERN)
  end
end
