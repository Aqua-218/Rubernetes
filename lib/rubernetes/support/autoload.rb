# frozen_string_literal: true

module Rubernetes
  module Autoload
    def self.register(namespace, directory, files)
      loaded = []
      files.each do |file, names|
        path = File.join(directory, file)
        names.each { |name| namespace.autoload(name, path) }
        # A directly required fragment may already have opened the class.
        # Ruby skips autoload for existing constants. Finish those files once
        # the rest of the namespace can be resolved.
        loaded << path if names.any? { |name| !namespace.autoload?(name) }
      end
      loaded.each { |path| require path }
    end
  end
  private_constant :Autoload
end
