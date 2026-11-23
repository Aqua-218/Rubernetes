# frozen_string_literal: true

module Rubernetes
  module Network
    class Netlink
      module LinkUpdate
        def link_set(name: nil, index: nil, mtu: nil, up: nil, master: nil, namespace: nil, namespace_fd: nil,
                     operation: nil, move_namespace: nil, **attributes)
          validate_namespace_target!(namespace_fd || namespace)
          validate_namespace_target!(move_namespace)
          unless kernel_adapter?
            return legacy_link_set(name: name, index: index, mtu: mtu, up: up, master: master, namespace: namespace,
                                   namespace_fd: namespace_fd, operation: operation, attributes: attributes)
          end

          namespace_target = namespace_fd || namespace
          if namespace_target && move_namespace.nil?
            begin
              return with_network_namespace(namespace_target, operation: operation) do
                link_set(name: name, index: index, mtu: mtu, up: up, master: master, operation: operation, **attributes)
              end
            rescue NetlinkError => error
              # A veth peer may still be in the caller namespace when the
              # caller asks us to move it.  The target-scoped lookup correctly
              # fails with ENODEV in that case; retry the RTM_SETLINK against
              # the source namespace while retaining IFLA_NET_NS_FD.  Any
              # permission/protocol error remains fail-closed.
              raise unless [Errno::ENODEV::Errno, Errno::ENOENT::Errno].include?(error.errno)

              move_namespace = namespace_target
            end
          end

          link_index = link_index(name || index, "link")
          flags = if up.nil?
                    0
                  else
                    (Support.bool(up) ? IFF_UP : 0)
                  end
          change = up.nil? ? 0 : IFF_CHANGE_UP
          payload = ifinfomsg(index: link_index, flags: flags, change: change)
          link_attributes = []
          link_attributes << attribute(IFLA_MTU, uint32(mtu, "MTU")) if mtu
          clear_master = Support.bool(Support.fetch(attributes, "clear_master", default: false))
          if master || clear_master
            link_attributes << attribute(IFLA_MASTER,
                                         master ? link_index(master, "master") : uint32(0, "master index"))
          end
          namespace_value = move_namespace || namespace_fd || namespace
          link_attributes << attribute(IFLA_NET_NS_FD, uint32(namespace_fd_value(namespace_value), "network namespace FD")) if namespace_value
          link_attributes.concat(encode_link_extra_attributes(attributes))
          response = request(type: RTM_SETLINK, payload: payload, attributes: link_attributes, operation: operation)
          bridge_hairpin = Support.fetch(attributes, "bridge_hairpin", default: nil)
          set_bridge_hairpin(link_index, bridge_hairpin, operation: operation) unless bridge_hairpin.nil?
          response
        end

        # A pod can return through its source bridge port after Service DNAT.
        # Bridge-port state is set after enslaving the veth with AF_UNSPEC.
        private def set_bridge_hairpin(index, enabled, operation:)
          mode = attribute(IFLA_BRPORT_MODE, [Support.bool(enabled) ? 1 : 0].pack("C"))
          info = attribute(IFLA_PROTINFO, TLV.encode_many([mode]), nested: true)
          request(type: RTM_SETLINK, payload: ifinfomsg(index: index, family: AF_BRIDGE),
                  attributes: [info], operation: operation)
        end
      end
    end
  end
end
