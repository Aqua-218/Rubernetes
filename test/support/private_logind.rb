# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require "rubernetes/platform/linux/dbus"

# A private dbus-daemon with a stand-in for systemd-logind and systemd's
# KillUnit, so the graceful node shutdown path runs over a real bus (SASL,
# RequestName routing, unix fd passing) without ever reaching the host's
# system bus.  The stand-in reads InhibitDelayMaxSec from the drop-in
# directory when it is "reloaded" (KillUnit systemd-logind.service SIGHUP),
# hands out delay inhibitor locks as pipe write ends -- a lock is held until
# every copy of its fd is closed, as with logind's fifo -- and emits
# PrepareForShutdown on request.
module PrivateLogind
  DBus = Rubernetes::Platform::Linux::DBus
  LOGIN1 = "org.freedesktop.login1"
  LOGIN1_PATH = "/org/freedesktop/login1"
  MANAGER = "org.freedesktop.login1.Manager"
  SYSTEMD1 = "org.freedesktop.systemd1"

  CONFIG = <<~XML
    <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
     "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
    <busconfig>
      <type>custom</type>
      <listen>unix:path=%<socket>s</listen>
      <auth>EXTERNAL</auth>
      <policy context="default">
        <allow user="*"/>
        <allow own="*"/>
        <allow send_destination="*" eavesdrop="true"/>
        <allow eavesdrop="true"/>
      </policy>
    </busconfig>
  XML

  def self.available? = system("command -v dbus-daemon >/dev/null 2>&1")

  # dbus-daemon on a socket under +directory+; #address is what
  # DBUS_SYSTEM_BUS_ADDRESS takes.
  class Daemon
    attr_reader :socket_path

    def initialize(directory)
      @directory = directory
      @socket_path = File.join(directory, "system_bus_socket")
    end

    def address = "unix:path=#{@socket_path}"

    def start
      File.delete(@socket_path) if File.exist?(@socket_path)
      config = File.join(@directory, "bus.conf")
      File.write(config, format(CONFIG, socket: @socket_path))
      @pid = Process.spawn("dbus-daemon", "--config-file=#{config}", "--nofork", "--nosyslog",
                           out: File.join(@directory, "dbus.log"), err: %i[child out])
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      until File.socket?(@socket_path)
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          raise "dbus-daemon did not start: #{File.read(File.join(@directory,
                                                                  "dbus.log"))}"
        end

        sleep 0.02
      end
      self
    end

    def stop
      return unless @pid

      Process.kill("TERM", @pid)
      Process.wait(@pid)
      @pid = nil
    rescue Errno::ESRCH, Errno::ECHILD
      @pid = nil
    end
  end

  Inhibitor = Struct.new(:what, :who, :why, :mode, :pid, :reader) do
    def held?
      return false if reader.closed?

      reader.read_nonblock(1, exception: false) == :wait_readable
    end
  end

  # login1 + systemd1 on the private bus.
  class Service
    attr_reader :calls, :config_directory, :reloads

    def initialize(address:, config_directory:, inhibit_delay_max_sec: 5)
      @address = address
      @config_directory = config_directory
      @base_delay = inhibit_delay_max_sec
      @delay = inhibit_delay_max_sec
      @calls = Queue.new
      @inhibitors = []
      @reloads = 0
      @mutex = Mutex.new
    end

    def start
      @connection = DBus::Connection.new(DBus.connect_address(@address))
      raise "could not own #{LOGIN1}" unless @connection.request_name(LOGIN1)
      raise "could not own #{SYSTEMD1}" unless @connection.request_name(SYSTEMD1)

      @stopping = false
      @thread = Thread.new { serve }
      self
    end

    def stop
      @stopping = true
      @thread&.join(2)
      @connection&.close
      @mutex.synchronize { @inhibitors.each { |inhibitor| inhibitor.reader.close unless inhibitor.reader.closed? } }
    end

    def inhibit_delay_usec = @mutex.synchronize { @delay * 1_000_000 }

    # systemd-inhibit --list: the locks still held.
    def inhibitors = @mutex.synchronize { @inhibitors.select(&:held?) }

    def prepare_for_shutdown(value)
      @connection.emit_signal(path: LOGIN1_PATH, interface: MANAGER, member: "PrepareForShutdown", signature: "b", body: [value])
    end

    private

    def serve
      until @stopping
        message = @connection.next_method_call(timeout: 0.1)
        handle(message) if message
      end
    rescue IOError, DBus::Error
      nil
    end

    def handle(message)
      @calls << [message.interface, message.member, message.body]
      case [message.interface, message.member]
      when ["org.freedesktop.DBus.Properties", "Get"]
        if message.body == [MANAGER, "InhibitDelayMaxUSec"]
          @connection.reply(message, signature: "v", body: [DBus::Typed.new("t", inhibit_delay_usec)])
        else
          @connection.reply_error(message, "org.freedesktop.DBus.Error.UnknownProperty", "unknown property #{message.body.inspect}")
        end
      when [MANAGER, "Inhibit"]
        what, who, why, mode = message.body
        reader, writer = IO.pipe
        @mutex.synchronize { @inhibitors << Inhibitor.new(what, who, why, mode, Process.pid, reader) }
        @connection.reply(message, signature: "h", body: [0], fds: [writer])
        writer.close
      when [MANAGER, "ListInhibitors"]
        rows = inhibitors.map { |entry| [entry.what, entry.who, entry.why, entry.mode, 0, entry.pid] }
        @connection.reply(message, signature: "a(ssssuu)", body: [rows])
      when ["org.freedesktop.systemd1.Manager", "KillUnit"]
        reload if message.body == ["systemd-logind.service", "all", 1]
        @connection.reply(message)
      else
        @connection.reply_error(message, "org.freedesktop.DBus.Error.UnknownMethod", "#{message.interface}.#{message.member}")
      end
    end

    # logind on SIGHUP: the drop-ins in lexical order, the last one wins.
    def reload
      delay = @base_delay
      Dir.glob(File.join(@config_directory, "*.conf")).each do |path|
        File.read(path).scan(/^\s*InhibitDelayMaxSec\s*=\s*(\d+)\s*$/) { |(seconds)| delay = Integer(seconds) }
      end
      @mutex.synchronize do
        @delay = delay
        @reloads += 1
      end
    end
  end
end
