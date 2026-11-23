# frozen_string_literal: true

require "digest"
require "socket"
require_relative "record_files"

module Rubernetes
  module Volume
    # open-iscsi sessions are shared by every LUN on their target and
    # interface. Persist ownership before login so a failed or interrupted
    # stage can be cleaned up after the manager is reconstructed.
    class ISCSISessions
      NOT_FOUND = [2, 21].freeze
      IFACE_NOT_FOUND = [6, *NOT_FOUND].freeze
      AUTH_FIELDS = %w[username password username_in password_in].freeze

      def initialize(data_dir:, fsync:, runner:)
        @data_dir = data_dir
        @records = RecordFiles.new(path: File.join(data_dir, "iscsi-sessions.json"), fsync: fsync)
        @runner = runner
      end

      def connect(backend, portal, credentials)
        portal = numeric_portal(portal)
        configuration = [@data_dir, backend.interface, backend.initiator, backend.target, backend.authentication_identity]
        iface = "rubernetes-#{Types.digest(configuration)[0, 24]}"
        node = {"portal" => portal, "target" => backend.target, "interface" => iface}
        key = Types.digest(node)
        synchronize do
          session = @records.load.find { |entry| entry["key"] == key } ||
                    node.merge("key" => key, "volumes" => [], "discoveryChap" => backend.discovery_chap?)
          session["volumes"] |= [backend.id]
          @records.write(key, session, durable: true)
          sid = session_id(session)
          unless sid
            configure_interface(backend, iface)
            connect_node(session, backend, credentials)
            sid = session_id(session)
          end
          raise Error, "iSCSI login returned without the expected session" unless sid

          iscsi(%W[-m session -r #{sid} --rescan], action: "rescan")
          sid
        end
      end

      def release(volume_id)
        synchronize do
          sessions = @records.load
          sessions.select { |session| session.fetch("volumes").include?(volume_id) }.each do |session|
            remaining = session.fetch("volumes") - [volume_id]
            key = session.fetch("key")
            if remaining.empty?
              disconnect_node(session)
              iface = session.fetch("interface")
              unless sessions.any? { |other| !other.equal?(session) && other["interface"] == iface }
                iscsi(%W[-m iface -I #{iface} -o delete], action: "remove interface", accepted: IFACE_NOT_FOUND)
              end
              @records.delete(key)
              session.delete("interface")
            else
              @records.write(key, session.merge("volumes" => remaining), durable: true)
            end
          end
        end
      end

      private

      def synchronize
        path = File.join(@data_dir, "iscsi-sessions.lock")
        File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |file|
          file.flock(File::LOCK_EX)
          yield
        end
      end

      def numeric_portal(portal)
        host, _, port = portal.rpartition(":")
        address = Addrinfo.getaddrinfo(host.delete_prefix("[").delete_suffix("]"), nil, nil, :STREAM, timeout: 10).first.ip_address
        address = "[#{address}]" if address.include?(":")
        "#{address}:#{port}"
      rescue SocketError
        raise Error, "cannot resolve iSCSI portal #{portal.inspect}"
      end

      def configure_interface(backend, iface)
        existing, status = inspect_interface(iface)
        template, = iscsi(%W[-m iface -I #{backend.interface} -o show], action: "read interface settings")
        properties = template.lines.each_with_object({}) do |line, result|
          key, value = line.chomp.split(" = ", 2)
          next unless key.match?(/\Aiface\.[a-z0-9_]+\z/) && key != "iface.iscsi_ifacename"
          next if value.nil? || value.empty? || value == "<empty>" || value == "0"

          result[key] = value
        end
        properties["iface.initiatorname"] = backend.initiator unless backend.initiator.empty?
        iscsi(%W[-m iface -I #{iface} -o new], action: "create interface") unless status == 0
        begin
          properties.each do |key, value|
            next if existing.lines.any? { |line| line.chomp == "#{key} = #{value}" }

            iscsi(["-m", "iface", "-I", iface, "-o", "update", "-n", key, "-v", value], action: "configure interface")
          end
        rescue Error
          iscsi(%W[-m iface -I #{iface} -o delete], action: "remove incompletely configured interface", accepted: IFACE_NOT_FOUND) if status != 0
          raise
        end
      end

      def inspect_interface(iface)
        iscsi(%W[-m iface -I #{iface} -o show], action: "inspect interface", accepted: IFACE_NOT_FOUND)
      end

      def connect_node(session, backend, credentials)
        node = node_arguments(session)
        if backend.discovery_chap?
          discovery = discovery_arguments(session)
          iscsi([*discovery, "-o", "new"], action: "create discovery record")
          set_auth(discovery, "discovery.sendtargets.auth", credentials)
          iscsi([*discovery, "--discover"], action: "discover target")
        else
          iscsi([*node, "-o", "new"], action: "create node record")
        end
        set_auth(node, "node.session.auth", credentials) if backend.session_chap?
        iscsi([*node, "-o", "update", "-n", "node.startup", "-v", "manual"], action: "configure node startup")
        iscsi([*node, "--login"], action: "login", accepted: [15])
      end

      def disconnect_node(session)
        return unless inspect_interface(session.fetch("interface"))[1] == 0

        node = node_arguments(session)
        iscsi([*node, "--logout"], action: "logout", accepted: NOT_FOUND)
        iscsi([*node, "-o", "delete"], action: "remove node record", accepted: NOT_FOUND)
        return unless session.fetch("discoveryChap")

        iscsi([*discovery_arguments(session), "-o", "delete"], action: "remove discovery record", accepted: NOT_FOUND)
      end

      def node_arguments(session)
        %W[-m node -p #{session.fetch("portal")} -T #{session.fetch("target")} -I #{session.fetch("interface")}]
      end

      def discovery_arguments(session)
        %W[-m discoverydb -t sendtargets -p #{session.fetch("portal")} -I #{session.fetch("interface")}]
      end

      def set_auth(arguments, prefix, credentials)
        username = credentials["#{prefix}.username"].to_s
        password = credentials["#{prefix}.password"].to_s
        raise ValidationError, "iSCSI CHAP authentication requires a username and password for #{prefix}" if username.empty? || password.empty?

        iscsi([*arguments, "-o", "update", "-n", "#{prefix}.authmethod", "-v", "CHAP"], action: "set CHAP method")
        AUTH_FIELDS.each do |field|
          key = "#{prefix}.#{field}"
          value = credentials[key].to_s
          next if value.empty?
          raise ValidationError, "iSCSI CHAP credentials contain control characters" if value.match?(/[\x00-\x1f\x7f]/)

          iscsi([*arguments, "-o", "update", "-n", key, "-v", value], action: "set CHAP credentials")
        end
      end

      def session_id(session)
        output, = iscsi(%w[-m session -P 1], action: "list sessions", accepted: NOT_FOUND)
        target = portal = iface = nil
        output.each_line do |line|
          case line.strip
          when /\ATarget: (\S+)/
            target = Regexp.last_match(1)
            portal = iface = nil
          when /\APersistent Portal: (\S+),\d+/
            portal = Regexp.last_match(1)
          when /\AIface Name: (\S+)/
            iface = Regexp.last_match(1)
          when /\ASID: (\d+)\z/
            return Regexp.last_match(1) if target == session["target"] && portal == session["portal"] && iface == session["interface"]
          end
        end
        nil
      end

      def iscsi(arguments, action:, accepted: [])
        output, status = @runner.call("iscsiadm", arguments, {})
        unless status == 0 || accepted.include?(status)
          # iscsiadm can echo command arguments that contain CHAP values.
          raise Error, "iSCSI #{action} failed (iscsiadm exit #{status})"
        end

        [output, status]
      end
    end
  end
end
