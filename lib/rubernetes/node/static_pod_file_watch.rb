# frozen_string_literal: true

require "fiddle"

module Rubernetes
  module Node
    # A directory watch keeps explicit removals visible even when the same
    # manifest has already been written again by the time we relist.
    class StaticPodFileWatch
      REMOVED = 0x240 # IN_MOVED_FROM | IN_DELETE
      CHANGED = REMOVED | 0x18c # IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
      LOST = 0xcc00 # IN_DELETE_SELF | IN_MOVE_SELF | IN_Q_OVERFLOW | IN_IGNORED
      HEADER_BYTES = 16

      def self.open(path)
        return unless RUBY_PLATFORM.include?("linux")

        new(path)
      rescue Fiddle::DLError, SystemCallError
        nil
      end

      attr_reader :io, :directory

      def initialize(path)
        @path = path
        @directory = File.directory?(path) ? path : File.dirname(path)
        libc = Fiddle::Handle::DEFAULT
        init = Fiddle::Function.new(libc["inotify_init1"], [Fiddle::TYPE_INT], Fiddle::TYPE_INT)
        add = Fiddle::Function.new(libc["inotify_add_watch"], [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
        descriptor = init.call(File::NONBLOCK)
        raise SystemCallError.new("inotify_init1", Fiddle.last_error) if descriptor.negative?

        @io = IO.for_fd(descriptor)
        @io.close_on_exec = true
        return unless add.call(descriptor, "#{@directory}\0", CHANGED | LOST).negative?

        @io.close
        raise SystemCallError.new("inotify_add_watch", Fiddle.last_error)
      end

      def consume
        data = @io.read_nonblock(64 * 1024, exception: false)
        return [[], true, true] if data.nil?
        return [[], false, false] if data == :wait_readable

        offset = 0
        removed = []
        lost = false
        changed = false
        while offset < data.bytesize
          _descriptor, flags, _cookie, length = data.unpack("lLLL", offset: offset)
          offset += HEADER_BYTES
          name = data.byteslice(offset, length).split("\0", 2).first.to_s
          offset += length
          lost ||= flags.anybits?(LOST)
          next if name.empty? || name.start_with?(".")

          path = File.join(@directory, name)
          next unless @directory == @path || path == @path

          changed = true
          removed << path if flags.anybits?(REMOVED)
        end
        lost ||= @directory != @path && File.directory?(@path)
        [removed.uniq, lost, changed || lost]
      end
    end
  end
end
