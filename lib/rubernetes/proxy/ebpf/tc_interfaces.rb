# frozen_string_literal: true

module Rubernetes
  module Proxy
    class LinuxEBPFAdapter
      module TCInterfaces
        private

        def normalize_hooks(hook)
          values = hook.to_sym == :tc ? %i[ingress egress] : [hook.to_sym]
          values.each do |value|
            raise ArgumentError, "unsupported TC hook #{value.inspect}" unless %i[ingress egress].include?(value)
          end
          values.freeze
        rescue NoMethodError
          raise ArgumentError, "TC hook must be ingress, egress, or tc"
        end

        # Accept one interface/ifindex or a list of them; the first entry is
        # the identity reported in attach results.
        ACCEPT_LOCAL_SYSCTL = "/proc/sys/net/ipv4/conf/%s/accept_local"

        def configure_accept_local!(ifindices)
          @accept_local_restore = {}
          ifindices.each do |index|
            name = Socket.getifaddrs.find { |address| address.ifindex == index }&.name
            next unless name

            path = format(ACCEPT_LOCAL_SYSCTL, name)
            next unless File.file?(path)

            previous = File.read(path).strip
            next if previous == "1"

            File.write(path, "1\n")
            @accept_local_restore[path] = previous
          end
        end

        def restore_accept_local!
          Hash(@accept_local_restore).each do |path, previous|
            File.write(path, "#{previous}\n") if File.file?(path)
          end
          @accept_local_restore = {}
        end

        def resolve_ifindices(interface:, ifindex:)
          interfaces = interface.is_a?(Array) ? interface : [interface]
          ifindices = ifindex.is_a?(Array) ? ifindex : [ifindex]
          pairs = if interfaces.length >= ifindices.length
                    interfaces.each_with_index.map do |name, index|
                      [name, ifindices[index]]
                    end
                  else
                    ifindices.each_with_index.map do |value, index|
                      [interfaces[index], value]
                    end
                  end
          resolved = pairs.map { |name, value| resolve_ifindex(interface: name, ifindex: value) }.uniq
          raise ArgumentError, "at least one TC interface is required" if resolved.empty?

          resolved.freeze
        end

        def resolve_ifindex(interface:, ifindex:)
          ifindex_value = ifindex.nil? ? nil : Integer(ifindex)
          return ifindex_value if ifindex_value && ifindex_value.positive?

          name = String(interface || "")
          raise ArgumentError, "a real interface name or positive ifindex is required for TC attach" if name.empty?

          entry = Socket.getifaddrs.find { |address| address.name == name && address.ifindex }
          resolved = entry&.ifindex
          raise Errno::ENODEV, "interface #{name.inspect} was not found" unless resolved && resolved.positive?

          resolved
        rescue TypeError, ArgumentError => error
          raise ArgumentError, "invalid TC interface reference: #{error.message}"
        end
      end
    end
  end
end
