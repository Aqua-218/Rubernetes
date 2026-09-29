# frozen_string_literal: true

require "fiddle"
require_relative "error"

module Rubernetes
  module Platform
    module Linux
      # Extended attributes on an open descriptor.  Only what layer extraction
      # needs: setting a file's xattrs while it is still open under the secure
      # rootfs (no path resolution), and reading one back for verification.
      module Xattr
        FSETXATTR = Fiddle::Function.new(Fiddle::Handle::DEFAULT["fsetxattr"],
                                         [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T, Fiddle::TYPE_INT],
                                         Fiddle::TYPE_INT)
        FGETXATTR = Fiddle::Function.new(Fiddle::Handle::DEFAULT["fgetxattr"],
                                         [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_SIZE_T],
                                         Fiddle::TYPE_SSIZE_T)
        MAX_VALUE_BYTES = 64 * 1024

        module_function

        def fset(fd, name, value, resource_id: "xattr")
          key = String(name)
          bytes = String(value).b
          raise ArgumentError, "xattr name must be non-empty" if key.empty? || key.include?("\0")
          raise ArgumentError, "xattr value exceeds #{MAX_VALUE_BYTES} bytes" if bytes.bytesize > MAX_VALUE_BYTES

          result = FSETXATTR.call(Integer(fd), key, bytes, bytes.bytesize, 0)
          errno = Fiddle.last_error
          raise Linux::Error.new(errno: errno, operation: "fsetxattr(#{key})", resource_id: resource_id) if result == -1

          true
        end

        # Returns the value as a binary String, or nil when the attribute is absent.
        def fget(fd, name, resource_id: "xattr")
          key = String(name)
          buffer = Fiddle::Pointer.malloc(MAX_VALUE_BYTES, Fiddle::RUBY_FREE)
          result = FGETXATTR.call(Integer(fd), key, buffer, MAX_VALUE_BYTES)
          errno = Fiddle.last_error
          if result == -1
            return nil if errno == Errno::ENODATA::Errno

            raise Linux::Error.new(errno: errno, operation: "fgetxattr(#{key})", resource_id: resource_id)
          end
          buffer[0, result].b
        end
      end
    end
  end
end
