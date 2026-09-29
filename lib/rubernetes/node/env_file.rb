# frozen_string_literal: true

module Rubernetes
  module Node
    # EnvFiles (Beta, on): env[].valueFrom.fileKeyRef reads a variable from a
    # file in one of the Pod's volumes -- typically an emptyDir an init
    # container wrote.  kubelet util/env ParseEnv: a strict subset of POSIX
    # shell, every value single-quoted:
    #
    #   VAR='value'            literal, no escapes or expansion
    #   VAR='multi
    #   line'                  newlines kept
    #   VAR='v' # comment      comment after the closing quote
    #   # comment, blank lines, leading whitespace ignored
    #   VAR = 'v'              rejected (whitespace before '=')
    #   VAR= 'v'               VAR is empty (whitespace after '=')
    module EnvFile
      class Error < StandardError; end

      MAX_SYMLINK_FOLLOWS = 255

      module_function

      # The value of +key+ ("" when the file does not set it).
      def parse(path, key)
        lines = begin
          File.read(path).split("\n", -1).map { |line| line.delete_suffix("\r") }
        rescue SystemCallError => error
          raise Error, "failed to open environment variable file #{path.inspect}: #{error.message}"
        end
        lines.pop if lines.last == ""
        index = 0
        while index < lines.length
          line_number = index + 1
          line = lines[index].sub(/\A[ \t]+/, "")
          index += 1
          next if line.empty? || line.start_with?("#")

          equals = line.index("=")
          raise Error, "invalid environment variable format at line #{line_number}: missing '='" if equals.nil?

          name_part = line[0, equals]
          name = name_part.sub(/[ \t]+\z/, "")
          raise Error, "invalid environment variable format at line #{line_number}: empty variable name" if name.empty?
          if name_part != name
            raise Error, "invalid environment variable format at line #{line_number}: whitespace before '=' is not allowed"
          end

          value_part = line[(equals + 1)..]
          trimmed = value_part.sub(/\A[ \t]+/, "")
          if value_part != trimmed
            return "" if name == key

            next
          end
          unless trimmed.start_with?("'")
            raise Error, "invalid environment variable format at line #{line_number}: value must be enclosed in single quotes"
          end

          value = +""
          rest = trimmed[1..]
          start = line_number
          loop do
            closing = rest.index("'")
            if closing
              value << rest[0, closing]
              after = rest[(closing + 1)..].sub(/\A[ \t]+/, "")
              unless after.empty? || after.start_with?("#")
                raise Error, "invalid environment variable format at line #{index}: unexpected content after closing quote"
              end
              return value if name == key

              break
            end
            value << rest << "\n"
            raise Error, "invalid environment variable format starting at line #{start}: unclosed single quote" if index >= lines.length

            rest = lines[index]
            index += 1
          end
        end
        ""
      end

      # filepath-securejoin SecureJoin: +path+ resolved beneath +root+ as if
      # +root+ were "/" (symlinks, absolute ones included, and ".." never
      # leave it).
      def secure_join(root, path)
        components = path.to_s.split("/").reject(&:empty?)
        resolved = []
        follows = 0
        until components.empty?
          component = components.shift
          next if component == "."

          if component == ".."
            resolved.pop
            next
          end
          candidate = File.join(root, *resolved, component)
          if File.symlink?(candidate)
            follows += 1
            raise Error, "too many symlinks in #{path}" if follows > MAX_SYMLINK_FOLLOWS

            link = File.readlink(candidate)
            resolved = [] if link.start_with?("/")
            components = link.split("/").reject(&:empty?) + components
            next
          end
          resolved << component
        end
        File.join(root, *resolved)
      end
    end
  end
end
