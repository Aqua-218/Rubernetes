# frozen_string_literal: true

module M0SourceInventory
  EXCLUDED_ROOTS = %w[.git artifacts build pkg tmp .bundle].freeze
  GENERATOR_SCRATCH = %r{\Aa11-generated\.[A-Za-z0-9]{6,}/}
  APP_RUNTIME = %r{\Aapps/[^/]+/(?:log|tmp|storage)/}
  # Dashboard credentials, compiled assets and metric stores belong to the
  # local host. Encrypted credentials and the database schema remain inputs.
  DASHBOARD_LOCAL = %r{
    \Aapps/dashboard/(?:
      config/(?:dashboard\.local\.env|master\.key|credentials/[^/]+\.key)
      |db/[^/]+\.sqlite3(?:-[^/]*)?
      |public/assets
    )(?:/|\z)
  }x
  DASHBOARD_DATA_DIRECTORY = %r{\Aapps/dashboard/data[^/]*\z}
  DASHBOARD_DATA_CONTENTS = %r{\Aapps/dashboard/data[^/]*/}
  EXCLUDED_PATTERNS = [GENERATOR_SCRATCH, APP_RUNTIME, DASHBOARD_LOCAL, DASHBOARD_DATA_CONTENTS].freeze

  module_function

  def excluded?(relative_path)
    relative_path.empty? || EXCLUDED_ROOTS.include?(relative_path.split("/", 2).first) ||
      EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(relative_path) }
  end

  def source_files(root)
    root = File.expand_path(root)
    prefix = root.end_with?(File::SEPARATOR) ? root : "#{root}/"
    directories = [root]
    files = []
    until directories.empty?
      directory = directories.pop
      children(directory).each do |name|
        path = File.join(directory, name)
        relative = path.delete_prefix(prefix)
        next if excluded?(relative)

        if directory_entry?(path)
          # These exclusions apply to descendants only. A regular file
          # with the same name still belongs in the source inventory.
          directories << path unless excluded?("#{relative}/")
          next
        end

        regular_file = block_given? ? yield(path) : File.file?(path)
        files << path if regular_file
      end
    end
    files.sort!
  end

  # A walker can prune the TSDB directory itself, while keeping a regular
  # file or symlink with a similar name as part of the source inventory.
  def dashboard_local?(relative_path)
    DASHBOARD_LOCAL.match?(relative_path) || DASHBOARD_DATA_CONTENTS.match?(relative_path) ||
      (block_given? && DASHBOARD_DATA_DIRECTORY.match?(relative_path) && yield)
  end

  def children(directory)
    Dir.children(directory)
  rescue Errno::ENOENT, Errno::ENOTDIR, Errno::EACCES, Errno::ELOOP, Errno::ENAMETOOLONG, Errno::EINVAL
    []
  end

  def directory_entry?(path)
    File.lstat(path).directory?
  rescue SystemCallError
    false
  end

  private_class_method :children, :directory_entry?
end
