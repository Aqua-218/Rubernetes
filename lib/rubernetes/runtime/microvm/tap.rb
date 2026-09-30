# frozen_string_literal: true

require "socket"

require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # TAP devices for the guest's virtio-net, created through the tun
      # driver ioctl interface (TUNSETIFF/TUNSETPERSIST/TUNSETOWNER) inside
      # the sandbox network namespace.  The device is persistent and owned
      # by the jailed Firecracker UID so the unprivileged VMM can open it.
      module Tap
        TUNSETIFF = 0x400454CA
        TUNSETPERSIST = 0x400454CB
        TUNSETOWNER = 0x400454CC
        TUNSETGROUP = 0x400454CE
        IFF_TAP = 0x0002
        IFF_NO_PI = 0x1000
        IFF_VNET_HDR = 0x4000
        IFNAMSIZ = 16
        SIOCSIFFLAGS = 0x8914
        SIOCGIFFLAGS = 0x8913
        SIOCGIFINDEX = 0x8933
        IFF_UP = 0x1

        module_function

        # Creates a persistent TAP device named +name+ in the calling
        # process's network namespace and returns {"name", "ifindex"}.
        def create(name, owner_uid:, owner_gid: nil, vnet_hdr: true)
          validate_name!(name)
          tun = File.open("/dev/net/tun", File::RDWR)
          flags = IFF_TAP | IFF_NO_PI
          flags |= IFF_VNET_HDR if vnet_hdr
          request = [name, flags].pack("a#{IFNAMSIZ}s")
          request << ("\0" * (40 - request.bytesize)) if request.bytesize < 40
          tun.ioctl(TUNSETIFF, request)
          tun.ioctl(TUNSETOWNER, Integer(owner_uid))
          tun.ioctl(TUNSETGROUP, Integer(owner_gid)) if owner_gid
          tun.ioctl(TUNSETPERSIST, 1)
          {"name" => name, "ifindex" => ifindex(name)}
        rescue SystemCallError => error
          raise NetworkError, "cannot create TAP #{name}: #{error.class}: #{error.message}"
        ensure
          tun&.close
        end

        def destroy(name)
          validate_name!(name)
          return false unless exists?(name)

          tun = File.open("/dev/net/tun", File::RDWR)
          request = [name, IFF_TAP | IFF_NO_PI].pack("a#{IFNAMSIZ}s")
          request << ("\0" * (40 - request.bytesize))
          tun.ioctl(TUNSETIFF, request)
          tun.ioctl(TUNSETPERSIST, 0)
          true
        rescue SystemCallError => error
          raise NetworkError, "cannot destroy TAP #{name}: #{error.class}: #{error.message}"
        ensure
          tun&.close
        end

        def up!(name)
          set_flags(name) { |flags| flags | IFF_UP }
        end

        def set_flags(name)
          socket = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
          request = [name].pack("a#{IFNAMSIZ}") + ("\0" * 24)
          socket.ioctl(SIOCGIFFLAGS, request)
          current = request.byteslice(IFNAMSIZ, 2).unpack1("s")
          updated = yield(current)
          request = [name, updated].pack("a#{IFNAMSIZ}s") + ("\0" * 22)
          socket.ioctl(SIOCSIFFLAGS, request)
          updated
        rescue SystemCallError => error
          raise NetworkError, "cannot change flags of #{name}: #{error.message}"
        ensure
          socket&.close
        end

        # sysfs is bound to the namespace it was mounted in, so the index is
        # read through the socket ioctl that answers for the calling
        # process's network namespace.
        def ifindex(name)
          socket = Socket.new(Socket::AF_INET, Socket::SOCK_DGRAM, 0)
          request = [name].pack("a#{IFNAMSIZ}") + ("\0" * 24)
          socket.ioctl(SIOCGIFINDEX, request)
          request.byteslice(IFNAMSIZ, 4).unpack1("l")
        ensure
          socket&.close
        end

        def exists?(name)
          ifindex(name)
          true
        rescue SystemCallError
          false
        end

        def validate_name!(name)
          raise NetworkError, "invalid interface name #{name.inspect}" unless name.is_a?(String) && name.match?(/\A[a-zA-Z0-9_.-]{1,15}\z/)
        end
      end
    end
  end
end
