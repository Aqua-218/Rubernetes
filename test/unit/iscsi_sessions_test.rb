# frozen_string_literal: true

require_relative "../test_helper"

class ISCSISessionsTest < Minitest::Test
  Volume = Rubernetes::Volume
  IQN = "iqn.2026-11.example:test"
  PORTAL = "192.0.2.60:3260"

  class OpenISCSI
    attr_reader :logins, :logouts
    attr_writer :reject_password

    def initialize
      @logins = @logouts = 0
      @interfaces = {}
      @session = nil
    end

    def call(command, args, _options)
      raise "unexpected command" unless command == "iscsiadm"

      iface = argument(args, "-I")
      case argument(args, "-m")
      when "iface"
        case argument(args, "-o")
        when "show"
          return ["iface.transport_name = tcp\n", 0] if iface == "default" || @interfaces.key?(iface)

          ["", 6]
        when "new"
          @interfaces[iface] = true
          ["", 0]
        when "delete"
          ["", @interfaces.delete(iface) ? 0 : 6]
        else
          ["", 0]
        end
      when "session"
        return ["", 0] if args.include?("--rescan")
        return ["", 21] unless @session

        ["Target: #{IQN} (non-flash)\nPersistent Portal: #{PORTAL},1\nIface Name: #{@session}\nSID: 8\n", 0]
      when "node"
        if args.include?("--login")
          @logins += 1
          @session = iface
        elsif args.include?("--logout")
          return ["", 21] unless @session

          @logouts += 1
          @session = nil
        elsif @reject_password && argument(args, "-n") == "node.session.auth.password"
          return ["iscsiadm rejected #{argument(args, "-v")}", 1]
        end
        ["", 0]
      end
    end

    private

    def argument(args, name)
      index = args.index(name)
      args[index + 1] if index
    end
  end

  def test_two_luns_share_a_session_across_manager_restart
    Dir.mktmpdir do |directory|
      runner = OpenISCSI.new
      first = backend(directory, "first", 0)
      other = backend(directory, "second", 3)

      assert_equal "8", session_store(directory, runner).connect(first, PORTAL, {})
      assert_equal "8", session_store(directory, runner).connect(other, PORTAL, {})
      assert_equal 1, runner.logins
      session_store(directory, runner).release(first.id)

      assert_equal 0, runner.logouts
      session_store(directory, runner).release(other.id)

      assert_equal 1, runner.logouts
      assert_empty session_records(directory)
    end
  end

  def test_failed_chap_command_keeps_credentials_out_of_error_and_journal
    Dir.mktmpdir do |directory|
      runner = OpenISCSI.new
      runner.reject_password = true
      volume = backend(directory, "first", 0, "chapAuthSession" => true, "secretRef" => {"name" => "chap"})
      credentials = {"node.session.auth.username" => "user", "node.session.auth.password" => "sensitive-password"}
      sessions = session_store(directory, runner)

      error = assert_raises(Volume::Error) { sessions.connect(volume, PORTAL, credentials) }
      refute_includes error.message, "sensitive-password"
      refute_includes session_records(directory).to_s, "sensitive-password"
      assert_equal 0, runner.logins
      sessions.release(volume.id)

      assert_empty session_records(directory)
    end
  end

  private

  def session_store(directory, runner)
    Volume::ISCSISessions.new(data_dir: directory, fsync: true, runner: runner)
  end

  def backend(directory, name, lun, **options)
    spec = {"targetPortal" => PORTAL, "iqn" => IQN, "lun" => lun}.merge(options)
    Volume::ISCSIBackend.new(root: directory, id: name, spec: spec, storage_devices: nil)
  end

  def session_records(directory)
    Volume::RecordFiles.read(File.join(directory, "iscsi-sessions.json"))
  end
end
