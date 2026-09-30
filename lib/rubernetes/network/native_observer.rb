# frozen_string_literal: true

require "ipaddr"
require "socket"

require_relative "errors"
require_relative "netlink"
require_relative "support"

module Rubernetes
  module Network
    # Kernel-backed rtnetlink dump observer.  It is deliberately separate from
    # Netlink's mutation API: ownership recovery must compare durable claims
    # with fresh kernel data and may not infer identity from the ledger alone.
    class NativeObserver
      def initialize(netlink: Netlink.new, include_loopback: true)
        @netlink = netlink
        @include_loopback = include_loopback == true
      end

      attr_reader :netlink

      def external_observer?
        # A recording/in-process adapter can expose a convenient dump-shaped
        # value, but it cannot prove kernel state after a restart. Native
        # ownership is available only when the rtnetlink socket adapter is the
        # actual production transport.
        @netlink.respond_to?(:adapter) && @netlink.adapter.is_a?(Netlink::SocketAdapter)
      end

      # Which dumps an operation's proof can possibly come from.  A readback is
      # a poll loop -- it re-reads until the kernel agrees -- so dumping the
      # address, route and neighbour tables to confirm a veth was created is
      # paid on every one of those polls, and a Pod attach does six readbacks.
      ACTION_KINDS = {
        "link_add" => %w[link], "link_set" => %w[link], "link_delete" => %w[link],
        "address_add" => %w[address], "address_delete" => %w[address],
        "route_add" => %w[route], "route_delete" => %w[route],
        "fdb_add" => %w[neighbour], "fdb_delete" => %w[neighbour]
      }.freeze

      def resources(namespace: nil, namespace_fd: nil, kinds: nil, link_name: nil)
        target = namespace_fd || namespace
        if target && @netlink.respond_to?(:with_namespace)
          return @netlink.with_namespace(target, operation: "network_observer") do
            resources(kinds: kinds, link_name: link_name)
          end
        end

        # Links are always needed: every other kind is reported against one.
        wanted = kinds.nil? ? nil : (Array(kinds).map(&:to_s) + ["link"]).uniq
        namespace_inode = File.stat(Netlink::THREAD_NAMESPACE_PATH).ino
        # A proof about one named link needs only that link.
        link_messages = if link_name && wanted == ["link"] && @netlink.respond_to?(:link_get)
                          begin
                            @netlink.link_get(name: link_name)
                          rescue NetlinkError
                            @netlink.link_dump
                          end
                        else
                          @netlink.link_dump
                        end
        links = parse_links(link_messages)
        links = links.reject { |entry| entry.fetch("name") == "lo" } unless @include_loopback
        by_index = links.to_h { |entry| [entry.fetch("index"), entry] }
        observed = links.map { |entry| link_resource(entry, namespace_inode) }
        return observed.freeze if wanted == ["link"]

        observed.concat(parse_addresses(@netlink.address_dump, by_index, namespace_inode)) if wanted.nil? || wanted.include?("address")
        observed.concat(parse_routes(@netlink.route_dump, by_index, namespace_inode)) if wanted.nil? || wanted.include?("route")
        observed.concat(parse_neighbours(@netlink.neighbor_dump, by_index, namespace_inode)) if wanted.nil? || wanted.include?("neighbour")
        observed.freeze
      rescue SystemCallError, NetlinkError => error
        raise NetlinkError.new("native network dump failed: #{error.message}",
                               errno: error.respond_to?(:errno) ? error.errno : nil,
                               operation: "network_observer")
      end

      alias observe resources
      alias list_resources resources

      def resources_for(operation)
        value = operation.respond_to?(:to_h) ? operation.to_h : operation
        params = Support.fetch(value, "parameters", default: {})
        if Support.fetch(value, "action") == "link_add" &&
           Support.fetch(params, "kind", default: nil).to_s == "veth" &&
           Support.fetch(params, "peer", default: nil)
          host_params = params.reject { |key, _| %w[namespace namespace_fd].include?(key.to_s) }
          host = matching_resource(value.merge("parameters" => host_params))
          # The peer's resource id is carried on the operation; the bare peer
          # name is "eth0" in every sandbox, so claiming under it would make the
          # second pod on a node collide with the first.
          peer_resource = Support.fetch(params, "peer_resource", default: nil) ||
                          "link:#{Support.fetch(params, "peer")}"
          peer = matching_resource(
            value.merge(
              "resource" => peer_resource,
              "parameters" => params.merge("name" => Support.fetch(params, "peer"), "kind" => "veth")
            )
          )
          # matching_resource answers with the observer's own inventory id,
          # which for the peer is derived from the interface name ("eth0" in
          # every sandbox).  The claim must use the plan's scoped resource id,
          # so carry it back on the proof.
          peer = peer.merge("id" => peer_resource).freeze if peer
          return [host, peer].compact.freeze
        end

        resource = matching_resource(value)
        resource ? [resource].freeze : [].freeze
      end

      def identity_for(operation)
        resources_for(operation).first&.fetch("identity", nil)
      end

      private

      def matching_resource(value)
        params = Support.fetch(value, "parameters", default: {})
        target = Support.fetch(params, "namespace_fd", "namespace", default: nil)
        if target && @netlink.respond_to?(:with_namespace)
          return @netlink.with_namespace(target, operation: "network_identity") do
            matching_resource(value.merge("parameters" => params.reject { |key, _| %w[namespace namespace_fd].include?(key.to_s) }))
          end
        end

        action = Support.fetch(value, "action")
        link_name = if %w[link_add link_set link_delete].include?(action.to_s) &&
                       Support.fetch(params, "index", default: nil).nil? &&
                       Support.fetch(params, "dev", "underlay", "underlay_dev", default: nil).nil?
                      Support.fetch(params, "name", default: nil)
                    end
        snapshot = resources(kinds: ACTION_KINDS[action.to_s], link_name: link_name&.to_s)
        case action
        when "link_add", "link_set", "link_delete"
          name = Support.fetch(params, "name", default: nil)
          index = Support.fetch(params, "index", default: nil)
          index = Integer(index) unless index.nil?
          expected_kind = Support.fetch(params, "kind", default: nil)&.to_s
          expected_mtu = Support.fetch(params, "mtu", default: nil)
          expected_vni = Support.fetch(params, "vni", "id", default: nil)
          expected_dstport = Support.fetch(params, "dstport", "destination_port", "port", default: nil)
          expected_learning = Support.fetch(params, "learning", default: nil)
          expected_underlay = Support.fetch(params, "dev", "underlay", "underlay_dev", default: nil)
          underlay = if expected_underlay
                       expected_underlay_index = begin
                         Integer(expected_underlay)
                       rescue StandardError
                         nil
                       end
                       snapshot.find do |entry|
                         next false unless entry.fetch("kind") == "link"

                         entry.dig("metadata", "name") == expected_underlay ||
                           (expected_underlay_index && entry.dig("metadata", "ifindex") == expected_underlay_index)
                       end
                     end
          resource = snapshot.find do |entry|
            next false unless entry.fetch("kind") == "link"
            next false unless (name && entry.dig("metadata", "name") == name) ||
                              (index && entry.dig("metadata", "ifindex") == index)

            metadata = entry.fetch("metadata")
            next false if expected_kind && metadata["kind"] != expected_kind
            next false if expected_mtu && metadata["mtu"] != Integer(expected_mtu)
            next false if expected_vni && metadata["vni"] != Integer(expected_vni)
            next false if expected_dstport && metadata["dstport"] != Integer(expected_dstport)
            next false if !expected_learning.nil? && metadata["learning"] != Support.bool(expected_learning)
            next false if underlay && metadata["underlay_ifindex"] != underlay.dig("metadata", "ifindex")

            true
          end
        when "address_add", "address_delete"
          address_value = Support.fetch(params, "address", default: nil).to_s
          address, embedded_prefix = address_value.split("/", 2)
          address = Support.ip(address, name: "network address").to_s
          prefix = Support.fetch(params, "prefix", default: nil) || embedded_prefix
          prefix = address_prefix(address, prefix)
          interface = Support.fetch(params, "interface", "name", default: nil)
          resource = snapshot.find do |entry|
            ready = Support.fetch(value, "action") != "address_add" ||
                    (entry.dig("metadata", "tentative") == false && entry.dig("metadata", "dad_failed") == false)
            entry.fetch("kind") == "address" && ready &&
              entry.dig("metadata", "address") == address &&
              (prefix.nil? || entry.dig("metadata", "prefix") == prefix) &&
              (interface.nil? || entry.dig("metadata", "ifname") == interface)
          end
        when "route_add", "route_delete"
          destination = Support.fetch(params, "destination", default: nil)
          destination = canonical_destination(destination)
          interface = Support.fetch(params, "interface", "dev", default: nil)
          gateway = Support.fetch(params, "via", "gateway", default: nil)
          gateway = Support.ip(gateway, name: "route gateway").to_s if gateway
          table = Integer(Support.fetch(params, "table", default: 254))
          metric_specified = params.key?("metric") || params.key?(:metric)
          metric = Integer(Support.fetch(params, "metric")) if metric_specified
          protocol = Integer(Support.fetch(params, "protocol", default: Netlink::RTPROT_STATIC))
          scope = Integer(Support.fetch(params, "scope", default: gateway ? Netlink::RT_SCOPE_UNIVERSE : Netlink::RT_SCOPE_LINK))
          route_type = Integer(Support.fetch(params, "route_type", "type", default: Netlink::RTN_UNICAST))
          resource = snapshot.find do |entry|
            entry.fetch("kind") == "route" &&
              entry.dig("metadata", "destination") == destination &&
              entry.dig("metadata", "gateway") == gateway &&
              entry.dig("metadata", "table") == table &&
              (!metric_specified || entry.dig("metadata", "metric") == metric) &&
              entry.dig("metadata", "protocol") == protocol &&
              entry.dig("metadata", "scope") == scope &&
              entry.dig("metadata", "route_type") == route_type &&
              interface_matches?(entry, interface)
          end
        when "fdb_add", "fdb_delete"
          mac = Support.fetch(params, "mac", default: nil)&.downcase
          destination = Support.ip(Support.fetch(params, "destination", default: nil), name: "FDB destination").to_s
          device = Support.fetch(params, "dev", "interface", default: nil)
          resource = snapshot.find do |entry|
            entry.fetch("kind") == "fdb" &&
              entry.dig("metadata", "mac") == mac &&
              entry.dig("metadata", "destination") == destination &&
              interface_matches?(entry, device)
          end
        end
        resource
      end

      def parse_links(messages)
        Array(messages).filter_map do |message|
          payload = message_payload(message)
          next if payload.bytesize < 16

          _family, _pad, _type, index, flags, _change = payload.byteslice(0, 16).unpack("CCS<l<L<L<")
          attributes = attributes_for(payload.byteslice(16..))
          name = c_string_value(attributes, Netlink::IFLA_IFNAME)
          next if name.nil? || name.empty?

          address = attributes_value(attributes, Netlink::IFLA_ADDRESS)
          master = attributes_uint32(attributes, Netlink::IFLA_MASTER)
          mtu = attributes_uint32(attributes, Netlink::IFLA_MTU)
          link_info = parse_link_info(attributes)
          {
            "index" => index,
            "name" => name,
            "flags" => flags,
            "up" => (flags & Netlink::IFF_UP).positive?,
            "mac" => address && format_mac(address),
            "master" => master,
            "mtu" => mtu
          }.merge(link_info).compact
        end
      end

      def parse_addresses(messages, by_index, namespace_inode)
        Array(messages).filter_map do |message|
          payload = message_payload(message)
          next if payload.bytesize < 8

          family, prefix, header_flags, _scope, index = payload.byteslice(0, 8).unpack("CCCCL<")
          attrs = attributes_for(payload.byteslice(8..))
          flags = attributes_uint32(attrs, Netlink::IFA_FLAGS) || header_flags
          raw = attributes_value(attrs, Netlink::IFA_LOCAL) || attributes_value(attrs, Netlink::IFA_ADDRESS)
          ip = decode_ip(raw, family)
          link = by_index[index]
          next unless ip && link

          identity = address_identity(namespace_inode, index, ip, prefix)
          {
            "kind" => "address",
            "id" => "address:#{link.fetch("name")}:#{ip}/#{prefix}",
            "identity" => identity,
            "owner" => "kernel-observer",
            "state" => "observed",
            "metadata" => {"netns_inode" => namespace_inode, "ifindex" => index, "ifname" => link.fetch("name"),
                           "address" => ip, "prefix" => prefix, "family" => family_name(family), "flags" => flags,
                           "tentative" => (flags & Netlink::IFA_F_TENTATIVE).positive?,
                           "dad_failed" => (flags & Netlink::IFA_F_DADFAILED).positive?}
          }
        end
      end

      def parse_routes(messages, by_index, namespace_inode)
        Array(messages).filter_map do |message|
          payload = message_payload(message)
          next if payload.bytesize < 12

          family, prefix, _src_len, _tos, table, protocol, scope, route_type, _flags = payload.byteslice(0, 12).unpack("CCCCCCCCL<")
          attrs = attributes_for(payload.byteslice(12..))
          # RTM_*MSG carries only the legacy u8 table field. Routes in a
          # table above 255 carry the authoritative value in RTA_TABLE.
          table = attributes_uint32(attrs, Netlink::RTA_TABLE) || table
          destination = decode_ip(attributes_value(attrs, Netlink::RTA_DST), family)
          destination ||= family == Netlink::AF_INET6 ? "::" : "0.0.0.0"
          destination = "#{destination}/#{prefix}"
          index = attributes_uint32(attrs, Netlink::RTA_OIF)
          link = by_index[index]
          # A route may be scoped by a gateway/table without an OIF. Keep it
          # in the inventory with ifindex=0 instead of dropping a durable
          # route claim; a requested device is still checked by identity_for.
          ifname = link && link.fetch("name")

          gateway = decode_ip(attributes_value(attrs, Netlink::RTA_GATEWAY), family)
          # Absence of RTA_PRIORITY is the kernel's canonical priority zero.
          # Persist the effective value so route identities never contain an
          # ambiguous missing metric.
          metric = attributes_uint32(attrs, Netlink::RTA_PRIORITY) || 0
          identity = route_identity(namespace_inode, index || 0, ifname, destination, gateway, table,
                                    metric, protocol, scope, route_type)
          {
            "kind" => "route",
            "id" => "route:#{ifname || index || 0}:#{destination}",
            "identity" => identity,
            "owner" => "kernel-observer",
            "state" => "observed",
            "metadata" => {"netns_inode" => namespace_inode, "ifindex" => index || 0, "ifname" => ifname,
                           "destination" => destination, "gateway" => gateway, "table" => table, "metric" => metric,
                           "protocol" => protocol, "scope" => scope, "route_type" => route_type,
                           "family" => family_name(family)}.compact
          }
        end
      end

      def parse_neighbours(messages, by_index, namespace_inode)
        Array(messages).filter_map do |message|
          payload = message_payload(message)
          next if payload.bytesize < 12

          family, _pad1, _pad2, index, _state, _flags, _type = payload.byteslice(0, 12).unpack("CCS<l<S<CC")
          # RTM_GETNEIGH also returns ARP/ND entries. They are not bridge FDB
          # ownership resources; only AF_BRIDGE records can prove a VXLAN or
          # bridge FDB claim and receive the FDB identity namespace.
          next unless family == Netlink::AF_BRIDGE

          attrs = attributes_for(payload.byteslice(12..))
          destination_raw = attributes_value(attrs, Netlink::NDA_DST)
          mac_raw = attributes_value(attrs, Netlink::NDA_LLADDR)
          link = by_index[index]
          next unless link && destination_raw && mac_raw

          destination = decode_neighbour_destination(destination_raw, family)
          mac = format_mac(mac_raw)
          identity = fdb_identity(namespace_inode, index, mac, destination)
          {
            "kind" => "fdb",
            "id" => "fdb:#{link.fetch("name")}:#{mac}:#{destination}",
            "identity" => identity,
            "owner" => "kernel-observer",
            "state" => "observed",
            "metadata" => {"netns_inode" => namespace_inode, "ifindex" => index, "ifname" => link.fetch("name"),
                           "mac" => mac, "destination" => destination, "family" => family_name(family)}
          }
        end
      end

      def link_resource(entry, namespace_inode)
        identity = link_identity(namespace_inode, entry.fetch("index"), entry.fetch("name"), entry["mac"])
        {
          "kind" => "link",
          "id" => "link:#{entry.fetch("name")}",
          "identity" => identity,
          "owner" => "kernel-observer",
          "state" => "observed",
          "metadata" => {"netns_inode" => namespace_inode, "ifindex" => entry.fetch("index"),
                         "name" => entry.fetch("name"), "ifname" => entry.fetch("name"), "mac" => entry["mac"],
                         "mtu" => entry["mtu"], "master_index" => entry["master"], "up" => entry.fetch("up")}
              .merge(entry.slice("kind", "vni", "underlay_ifindex", "local", "group", "learning", "dstport"))
        }
      end

      def message_payload(message)
        message.respond_to?(:payload) ? message.payload : Support.fetch(message, "payload", default: "")
      end

      def attributes_for(bytes)
        return [] if bytes.nil? || bytes.empty?

        Netlink::TLV.decode(bytes)
      end

      def attributes_value(attributes, type)
        attributes.find { |entry| entry.fetch("type") == type }&.fetch("value")
      end

      def c_string_value(attributes, type)
        value = attributes_value(attributes, type)
        value&.delete_suffix("\0")
      end

      def attributes_uint32(attributes, type)
        value = attributes_value(attributes, type)
        value && value.bytesize >= 4 ? value.unpack1("L<") : nil
      end

      def parse_link_info(attributes)
        value = attributes_value(attributes, Netlink::IFLA_LINKINFO)
        return {} unless value

        info = attributes_for(value)
        kind = c_string_value(info, Netlink::IFLA_INFO_KIND)
        result = {"kind" => kind}
        return result.compact unless kind == "vxlan"

        data_value = attributes_value(info, Netlink::IFLA_INFO_DATA)
        data = data_value ? attributes_for(data_value) : []
        result["vni"] = attributes_uint32(data, Netlink::IFLA_VXLAN_ID)
        result["underlay_ifindex"] = attributes_uint32(data, Netlink::IFLA_VXLAN_LINK)
        result["local"] = decode_ip(attributes_value(data, Netlink::IFLA_VXLAN_LOCAL), Netlink::AF_INET)
        result["local"] ||= decode_ip(attributes_value(data, Netlink::IFLA_VXLAN_LOCAL6), Netlink::AF_INET6)
        result["group"] = decode_ip(attributes_value(data, Netlink::IFLA_VXLAN_GROUP), Netlink::AF_INET)
        result["group"] ||= decode_ip(attributes_value(data, Netlink::IFLA_VXLAN_GROUP6), Netlink::AF_INET6)
        learning = attributes_value(data, Netlink::IFLA_VXLAN_LEARNING)
        result["learning"] = learning && !learning.byteslice(0, 1).unpack1("C").zero?
        port = attributes_value(data, Netlink::IFLA_VXLAN_PORT)
        result["dstport"] = port.unpack1("S>") if port && port.bytesize >= 2
        result.compact
      end

      def decode_ip(raw, family)
        return nil unless raw

        expected = if family == Netlink::AF_INET
                     4
                   else
                     family == Netlink::AF_INET6 ? 16 : nil
                   end
        return nil unless expected && raw.bytesize >= expected

        IPAddr.new_ntoh(raw.byteslice(0, expected)).to_s
      rescue IPAddr::InvalidAddressError
        nil
      end

      def address_prefix(address, explicit_prefix)
        raise ValidationError, "network address prefix is required" if explicit_prefix.nil?

        prefix = Integer(explicit_prefix)
        max = IPAddr.new(address).ipv4? ? 32 : 128
        raise ValidationError, "network address prefix is out of range" unless prefix.between?(0, max)

        prefix
      rescue ArgumentError, IPAddr::InvalidAddressError
        nil
      end

      def canonical_destination(value)
        network, prefix = Support.cidr(value, name: "route destination")
        "#{network}/#{prefix}"
      rescue StandardError
        value.to_s
      end

      def interface_matches?(entry, value)
        return true if value.nil?

        metadata = entry.fetch("metadata")
        return true if metadata["ifname"] == value

        Integer(value) == metadata["ifindex"]
      rescue ArgumentError, TypeError
        false
      end

      def decode_neighbour_destination(raw, family)
        return format_mac(raw) if family == Netlink::AF_BRIDGE && raw.bytesize == 6
        # VXLAN FDB entries use AF_BRIDGE for ndmsg while NDA_DST contains
        # the remote VTEP address (4 or 16 bytes), not a six-byte MAC.
        return IPAddr.new_ntoh(raw).to_s if family == Netlink::AF_BRIDGE && [4, 16].include?(raw.bytesize)

        decode_ip(raw, family) || raw.unpack1("H*")
      end

      def format_mac(raw)
        return nil unless raw && raw.bytesize >= 6

        raw.byteslice(0, 6).unpack1("H12").scan(/../).join(":")
      end

      def family_name(family)
        return "ipv4" if family == Netlink::AF_INET
        return "ipv6" if family == Netlink::AF_INET6
        return "bridge" if family == Netlink::AF_BRIDGE

        family.to_s
      end

      def link_identity(netns_inode, index, name, mac)
        "link:netns=#{netns_inode}:ifindex=#{index}:name=#{name}:mac=#{mac || "-"}"
      end

      def address_identity(netns_inode, index, address, prefix)
        "address:netns=#{netns_inode}:ifindex=#{index}:address=#{address}/#{prefix}"
      end

      def route_identity(netns_inode, index, ifname, destination, gateway, table, metric, protocol, scope, route_type)
        "route:netns=#{netns_inode}:ifindex=#{index}:ifname=#{ifname || "-"}:destination=#{destination}:" \
          "gateway=#{gateway || "-"}:table=#{table}:metric=#{metric || "-"}:protocol=#{protocol}:" \
          "scope=#{scope}:type=#{route_type}"
      end

      def fdb_identity(netns_inode, index, mac, destination)
        "fdb:netns=#{netns_inode}:ifindex=#{index}:mac=#{mac}:destination=#{destination}"
      end
    end
  end
end
