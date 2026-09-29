# frozen_string_literal: true

# Typed cgroup v2 operations used by the Native runtime.  This adapter owns
# Linux file layout and parsing only; policy and QoS decisions remain in Ruby
# runtime code.  Every filesystem operation can be injected for deterministic
# L0/L1 tests.

require "fileutils"

module Rubernetes
  module Platform
    module Linux
      class CgroupV2
        class Error < StandardError; end
        class Unsupported < Error; end
        class InvalidPath < Error; end
        class Busy < Error; end

        Probe = Data.define(:available, :controllers, :subtree_control, :reason) do
          def available?
            available
          end

          def to_h
            {
              "available" => available,
              "controllers" => controllers,
              "subtree_control" => subtree_control,
              "reason" => reason
            }
          end
        end
        Handle = Data.define(:path, :qos, :pod_id, :container_id, :identity) do
          def to_h
            value = {
              "path" => path,
              "qos" => qos,
              "pod_id" => pod_id,
              "container_id" => container_id,
              "identity" => identity
            }
            # cgroup v2 exposes a stable kernel identity through the cgroup
            # directory inode.  Keep it as metadata rather than changing the
            # public Handle shape so injected/fake adapters remain compatible.
            value["cgroup_inode"] = File.stat(path).ino if File.directory?(path)
            value
          rescue SystemCallError
            value
          end
        end
        Stats = Data.define(:cpu, :memory, :io, :pids, :pressure, :events) do
          def to_h
            {
              "cpu" => cpu,
              "memory" => memory,
              "io" => io,
              "pids" => pids,
              "pressure" => pressure,
              "events" => events
            }
          end
        end

        DEFAULT_ROOT = "/sys/fs/cgroup".freeze
        HIERARCHY_PREFIX = "rubernetes".freeze
        QOS_CLASSES = %w[guaranteed burstable besteffort].freeze
        CONTROLLERS = %w[cpu cpuset io memory pids].freeze
        # Controllers that must be delegated down the rubernetes hierarchy.
        # cpu/memory/pids are mandatory (§5.8.8); io and cpuset are enabled
        # whenever the parent offers them so io.max/cpuset.cpus become
        # writable on leaves without a second configuration pass.
        REQUIRED_CONTROLLERS = %w[cpu memory pids].freeze
        OPTIONAL_CONTROLLERS = %w[io cpuset].freeze
        CONTROLLER_FILES = {
          "cpu.max" => :cpu_max,
          "cpu.weight" => :cpu_weight,
          "memory.min" => :memory_min,
          "memory.low" => :memory_low,
          "memory.high" => :memory_high,
          "memory.max" => :memory_max,
          "memory.swap.max" => :memory_swap_max,
          "memory.oom.group" => :memory_oom_group,
          "io.max" => :io_max,
          "io.weight" => :io_weight,
          "pids.max" => :pids_max,
          "cpuset.cpus" => :cpuset_cpus,
          "cpuset.mems" => :cpuset_mems
        }.freeze
        # Files read back after configuration so a caller can prove the
        # kernel accepted exactly the requested limits.
        READBACK_FILES = %w[cpu.max cpu.weight memory.min memory.low memory.high memory.max memory.swap.max memory.oom.group pids.max].freeze
        STAT_FILES = {
          cpu: "cpu.stat",
          memory: "memory.stat",
          io: "io.stat",
          pids: "pids.current",
          pressure: "memory.pressure",
          events: "memory.events"
        }.freeze

        # A small adapter keeps production calls explicit and makes fake I/O
        # tests independent of the host's cgroup mount.
        class FileAdapter
          def exists?(path)
            File.exist?(path)
          end

          def directory?(path)
            File.directory?(path)
          end

          def read(path)
            File.binread(path)
          end

          def write(path, value)
            File.binwrite(path, String(value))
          end

          def mkdir_p(path)
            FileUtils.mkdir_p(path)
          end

          def delete(path)
            Dir.rmdir(path)
          end

          def child_directories(path)
            Dir.children(path).filter_map do |entry|
              child = File.join(path, entry)
              child if File.directory?(child)
            end
          end
        end

        def initialize(root: DEFAULT_ROOT, adapter: FileAdapter.new, hierarchy: HIERARCHY_PREFIX)
          @root = File.expand_path(String(root))
          @adapter = adapter
          @hierarchy = validate_component(hierarchy, "hierarchy")
          freeze_root
        end

        attr_reader :root, :hierarchy

        def probe
          unless @adapter.directory?(@root)
            return Probe.new(available: false, controllers: [], subtree_control: [], reason: "cgroup root is not a directory")
          end

          controllers = read_words(File.join(@root, "cgroup.controllers"))
          subtree_control = read_words(File.join(@root, "cgroup.subtree_control"))
          missing = %w[cpu memory pids].reject { |name| controllers.include?(name) }
          reason = missing.empty? ? nil : "required controllers are unavailable: #{missing.join(", ")}"
          Probe.new(available: reason.nil?, controllers: controllers.freeze, subtree_control: subtree_control.freeze, reason: reason)
        rescue SystemCallError => error
          Probe.new(available: false, controllers: [], subtree_control: [], reason: "#{error.class}: #{error.message}")
        end

        def probe!
          result = probe
          raise Unsupported, result.reason || "cgroup v2 is unavailable" unless result.available?

          result
        end

        def available?
          probe.available?
        end

        def hierarchy_path(qos:)
          qos = normalize_qos(qos)
          File.join(@root, @hierarchy, qos)
        end

        def path(qos:, pod_id:, container_id:)
          qos_path = hierarchy_path(qos: qos)
          pod = validate_component(pod_id, "pod_id")
          container = validate_component(container_id, "container_id")
          File.join(qos_path, pod, container)
        end

        # Create `<qos>/<pod>/<container>` and apply limits in one ownership
        # unit.  Acquisition order: pod directory -> controller delegation ->
        # leaf directory -> pod limits -> leaf limits.  Any failure releases
        # what this call created in reverse order (R-1.3, §5.8.4) so a
        # rejected limit never leaves an unowned cgroup behind.
        def create(qos:, pod_id:, container_id:, identity: nil, limits: nil, pod_limits: nil)
          target = path(qos: qos, pod_id: pod_id, container_id: container_id)
          pod_path = File.dirname(target)
          created = []
          begin
            [hierarchy_path(qos: qos), pod_path].each do |directory|
              next if @adapter.directory?(directory)

              @adapter.mkdir_p(directory)
              created << directory
            end
            ensure_controllers!(pod_path)
            unless @adapter.directory?(target)
              @adapter.mkdir_p(target)
              created << target
            end
            handle = Handle.new(
              path: target,
              qos: normalize_qos(qos),
              pod_id: validate_component(pod_id, "pod_id"),
              container_id: validate_component(container_id, "container_id"),
              identity: String(identity || target).freeze
            )
            configure_path(pod_path, pod_limits) unless pod_limits.nil? || pod_limits.empty?
            configure(handle, limits) unless limits.nil? || limits.empty?
            handle
          rescue StandardError => error
            rollback_created(created, error)
            raise
          end
        rescue SystemCallError => error
          raise Error, "failed to create cgroup #{target}: #{error.message}"
        end

        alias create_cgroup create

        def configure(handle, limits)
          configure_path(handle_path(handle), limits)
          handle
        end

        alias apply_limits configure

        # Pod-level (`<qos>/<pod>`) limits share the leaf encoding.  The pod
        # directory is an interior node with no processes, so writing limits
        # there is legal under the no-internal-processes rule.
        def configure_pod(handle, limits)
          configure_path(File.dirname(handle_path(handle)), limits)
          handle
        end

        # Read the limit files the kernel exposes for this cgroup.  Missing
        # files (controller not delegated) are reported as nil rather than
        # raising, so the caller can prove which controllers are enforced.
        def limits_readback(handle, files: READBACK_FILES)
          target = handle_path(handle)
          Array(files).each_with_object({}) do |name, result|
            file = File.join(target, name)
            result[name] = @adapter.exists?(file) ? read_file(file).strip : nil
          end
        end

        def pod_limits_readback(handle, files: READBACK_FILES)
          pod_path = File.dirname(handle_path(handle))
          Array(files).each_with_object({}) do |name, result|
            file = File.join(pod_path, name)
            result[name] = @adapter.exists?(file) ? read_file(file).strip : nil
          end
        end

        # memory.events counts OOM kills cumulatively; callers compare against
        # a baseline captured at container start to attribute a kill once.
        def oom_kill_count(handle)
          Integer(events(handle).fetch("oom_kill", 0))
        end

        def attach(handle, pid:)
          write_file(File.join(handle_path(handle), "cgroup.procs"), Integer(pid).to_s)
          true
        rescue ArgumentError
          raise ArgumentError, "pid must be an integer"
        end

        alias add_process attach

        # A write-only descriptor on +handle+'s cgroup.procs, for a process
        # that joins the cgroup itself at the last moment (writing "0").  The
        # kernel checks the migration against the credentials and cgroup
        # namespace of the opener, so the descriptor still works after the
        # process has dropped privileges and entered the container's
        # namespaces.  Nil for an in-memory adapter.
        def open_procs(handle)
          return nil unless @adapter.is_a?(FileAdapter)

          File.open(File.join(handle_path(handle), "cgroup.procs"), File::WRONLY)
        end

        # kubelet allows a pod cgroup this long to empty out after a kill.
        KILL_QUIESCE_SECONDS = 30.0
        KILL_REPEAT_SECONDS = 1.0

        def kill(handle)
          target = handle_path(handle)
          kill_path = File.join(target, "cgroup.kill")
          raise Unsupported, "cgroup.kill is unavailable for #{target}" unless @adapter.exists?(kill_path)

          write_file(kill_path, "1")
          # A task can sit uninterruptible (flushing an overlay, unmounting)
          # for longer than a couple of seconds on a loaded node, and a task
          # that entered the cgroup after the first write never received the
          # signal at all.  Five seconds with a single kill turned that into a
          # hard failure -- observed as
          # "cgroup did not quiesce after cgroup.kill" roughly once per
          # thousand container cycles.  Wait as long as the kubelet does and
          # re-issue the kill while waiting.
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + KILL_QUIESCE_SECONDS
          next_kill = Process.clock_gettime(Process::CLOCK_MONOTONIC) + KILL_REPEAT_SECONDS
          loop do
            populated, current = cgroup_population(target)
            return true if Integer(populated).zero? && Integer(current).zero?

            now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if now >= deadline
              # No live task remains: what is left is an entry for a process
              # that has exited and not yet been reaped, which disappears on
              # its own and which rmdir reports as EBUSY for the caller to
              # retry.  That is quiesced for our purposes.
              return true if Integer(populated).zero?

              raise Busy, "cgroup did not quiesce after cgroup.kill: #{target}"
            end
            if now >= next_kill
              write_file(kill_path, "1")
              next_kill = now + KILL_REPEAT_SECONDS
            end
            sleep 0.01
          end
        rescue Errno::ENOENT
          true
        end

        def events(handle)
          parse_key_values(read_file(File.join(handle_path(handle), "memory.events")))
        end

        def stats(handle)
          target = handle_path(handle)
          Stats.new(
            cpu: parse_key_values(read_file(File.join(target, STAT_FILES.fetch(:cpu)))),
            memory: parse_key_values(read_file(File.join(target, STAT_FILES.fetch(:memory)))),
            io: parse_key_values(read_file(File.join(target, STAT_FILES.fetch(:io)))),
            pids: parse_scalar(read_file(File.join(target, STAT_FILES.fetch(:pids)))),
            pressure: parse_key_values(read_file(File.join(target, STAT_FILES.fetch(:pressure)))),
            events: parse_key_values(read_file(File.join(target, STAT_FILES.fetch(:events))))
          )
        rescue Errno::ENOENT => error
          raise Error, "cgroup stats are unavailable for #{target}: #{error.message}"
        end

        # What the kubelet's stats provider reads for one cgroup (cAdvisor
        # setMemoryStats / setCPUStats inputs): cpu.stat, memory.stat and
        # memory.current, of the handle's cgroup or (+pod: true+) of the Pod
        # cgroup above it.  Missing files are nil.
        # The cgroup's live accounting, as the Summary API and the kubelet's
        # cAdvisor endpoint read it: cpu.stat, memory.stat and the scalar
        # files cAdvisor's container metrics are built from (limits, swap,
        # peak, memory.events, pids, io.stat), plus the cgroup's path
        # relative to the root (cAdvisor's container id).
        SCALAR_FILES = %w[memory.current memory.max memory.low memory.min memory.high memory.peak
                          memory.swap.current memory.swap.max pids.current pids.max cpu.weight].freeze

        def usage(handle, pod: false)
          target = handle_path(handle)
          target = File.dirname(target) if pod
          read = lambda do |name|
            file = File.join(target, name)
            @adapter.exists?(file) ? read_file(file) : nil
          end
          cpu = read.call("cpu.stat")
          memory = read.call("memory.stat")
          result = {"cpu" => cpu && parse_key_values(cpu), "memory" => memory && parse_key_values(memory)}
          SCALAR_FILES.each do |name|
            value = read.call(name)
            # "max" (no limit) reads as nil.
            result[name] = value && (value.strip == "max" ? nil : parse_scalar(value))
          end
          events = read.call("memory.events")
          result["memory.events"] = events && parse_key_values(events)
          cpu_max = read.call("cpu.max")
          result["cpu.max"] = cpu_max && cpu_max.split
          io = read.call("io.stat")
          result["io.stat"] = io && parse_io_stat(io)
          procs = read.call("cgroup.procs")
          result["cgroup.procs"] = procs && procs.split.filter_map { |pid| Integer(pid, exception: false) }
          result["path"] = target.delete_prefix(@root).then { |rel| rel.start_with?("/") ? rel : "/#{rel}" }
          result
        end

        # io.stat: one line per device, "MAJ:MIN rbytes=.. wbytes=.. rios=.. wios=.. dbytes=.. dios=..".
        def parse_io_stat(text)
          String(text).lines.each_with_object({}) do |line, devices|
            tokens = line.split
            device = tokens.shift
            next if device.nil? || device.empty?

            devices[device] = tokens.each_with_object({}) do |token, values|
              key, value = token.split("=", 2)
              values[key] = Integer(value, exception: false) || 0 if key && value
            end
          end
        end

        def freeze(handle, frozen: true)
          write_file(File.join(handle_path(handle), "cgroup.freeze"), frozen ? "1" : "0")
          frozen
        end

        def remove(handle, force: false)
          target = handle_path(handle)
          return true unless @adapter.directory?(target)

          populated, current = cgroup_population(target)
          if !force && (Integer(populated).positive? || Integer(current).positive?) && @adapter.is_a?(FileAdapter)
            # Process exit and cgroup.events propagation are not atomic.  A
            # bounded quiescence wait avoids reporting a leak while the
            # kernel is completing an already-confirmed process teardown.
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 1.0
            while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
              sleep 0.01
              populated, current = cgroup_population(target)
              break if Integer(populated).zero? && Integer(current).zero?
            end
          end
          if !force && (Integer(populated).positive? || Integer(current).positive?)
            raise Busy, "cannot remove populated cgroup #{target}"
          end

          @adapter.delete(target)
          remove_empty_pod_parent(target)
          true
        rescue Errno::ENOENT
          true
        rescue SystemCallError => error
          raise Error, "failed to remove cgroup #{target}: #{error.message}"
        end

        alias remove_cgroup remove

        # Enumerates only cgroups below this adapter's configured hierarchy.
        # An injected scanner may provide a richer inventory for hosts where
        # directory enumeration is not available; otherwise the file adapter
        # is read directly and identities are derived from the immutable path
        # components.
        def resources
          if @adapter.respond_to?(:list_cgroups)
            return Array(@adapter.list_cgroups(root: @root, hierarchy: @hierarchy)).freeze
          end
          return [].freeze unless @adapter.is_a?(FileAdapter)

          base = File.join(@root, @hierarchy)
          return [].freeze unless File.directory?(base)

          resources = []
          QOS_CLASSES.each do |qos|
            qos_path = File.join(base, qos)
            next unless File.directory?(qos_path)

            Dir.children(qos_path).sort.each do |pod_id|
              pod_path = File.join(qos_path, pod_id)
              next unless File.directory?(pod_path) && pod_id.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)

              Dir.children(pod_path).sort.each do |container_id|
                next unless container_id.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
                target = File.join(pod_path, container_id)
                next unless File.directory?(target)

                identity = container_id == "sandbox" ? "cgroup:#{pod_id}" : "cgroup:#{pod_id}:#{container_id}"
                resources << Handle.new(path: target, qos: qos, pod_id: pod_id,
                                        container_id: container_id, identity: identity.freeze)
              end
            end
          end
          resources.freeze
        rescue SystemCallError => error
          raise Error, "failed to enumerate cgroup hierarchy #{@root}/#{@hierarchy}: #{error.message}"
        end

        alias handles resources

        def lookup(value)
          path = value.respond_to?(:path) ? value.path : String(value)
          resources.find { |handle| handle.path == path } || raise(Error, "unknown cgroup handle #{path}")
        end

        private

        def cgroup_population(target)
          populated = parse_key_values(read_file(File.join(target, "cgroup.events"))).fetch("populated", 0)
          current = if @adapter.exists?(File.join(target, "pids.current"))
            parse_scalar(read_file(File.join(target, "pids.current")))
          else
            0
          end
          [populated, current]
        end

        # The per-Pod directory is created as an implementation detail by
        # mkdir_p.  Once its last sandbox/container leaf is gone it must also
        # be removed, otherwise each completed Pod leaks one cgroup directory.
        # Custom adapters can opt into this bounded cleanup contract.
        def remove_empty_pod_parent(target)
          return unless @adapter.respond_to?(:child_directories)

          pod_parent = File.dirname(target)
          qos_parent = File.dirname(pod_parent)
          expected_qos_parent = hierarchy_path(qos: File.basename(qos_parent))
          return unless qos_parent == expected_qos_parent
          return unless @adapter.directory?(pod_parent)
          return unless Array(@adapter.child_directories(pod_parent)).empty?

          @adapter.delete(pod_parent)
        rescue Errno::ENOENT
          nil
        end

        # Controllers are enabled on every ancestor from the rubernetes root
        # down to the pod directory before a leaf is created.  cgroup v2 only
        # exposes controller files to children of a parent whose
        # cgroup.subtree_control lists the controller; a directory tree
        # without delegation would accept mkdir but reject every limit write
        # with EACCES/ENOENT.  Enabling is top-down because a controller can
        # be enabled on a child only after it appears in the child's
        # cgroup.controllers, which the parent's delegation produces.
        def ensure_controllers!(leaf_parent)
          base = File.join(@root, @hierarchy)
          target = File.expand_path(String(leaf_parent))
          raise InvalidPath, "cgroup parent escapes configured hierarchy" unless target == base || target.start_with?(base + File::SEPARATOR)

          chain = [base]
          relative = target.delete_prefix(base).split(File::SEPARATOR).reject(&:empty?)
          relative.each { |component| chain << File.join(chain.last, component) }
          chain.each do |parent|
            next unless @adapter.directory?(parent)

            controllers = read_words(File.join(parent, "cgroup.controllers"))
            enabled = read_words(File.join(parent, "cgroup.subtree_control"))
            missing_required = REQUIRED_CONTROLLERS.reject { |name| controllers.include?(name) }
            unless missing_required.empty?
              raise Unsupported, "cgroup #{parent} does not offer required controllers: #{missing_required.join(", ")}"
            end
            wanted = (REQUIRED_CONTROLLERS + OPTIONAL_CONTROLLERS).select { |name| controllers.include?(name) && !enabled.include?(name) }
            next if wanted.empty?

            # The kernel rejects a write that mixes an unsupported optional
            # controller with required ones as a whole, so optional
            # controllers are enabled one at a time after the required set.
            required_now = wanted & REQUIRED_CONTROLLERS
            write_file(File.join(parent, "cgroup.subtree_control"), required_now.map { |name| "+#{name}" }.join(" ")) unless required_now.empty?
            (wanted & OPTIONAL_CONTROLLERS).each do |name|
              write_file(File.join(parent, "cgroup.subtree_control"), "+#{name}")
            end
            after = read_words(File.join(parent, "cgroup.subtree_control"))
            still_missing = REQUIRED_CONTROLLERS.reject { |name| after.include?(name) }
            raise Unsupported, "cgroup #{parent} did not enable #{still_missing.join(", ")}" unless still_missing.empty?
          end
          true
        rescue SystemCallError => error
          raise Unsupported, "cannot enable cgroup v2 controllers: #{error.message}"
        end

        def configure_path(target, limits)
          normalized = normalize_limits(limits)
          normalized.each do |name, value|
            file = CONTROLLER_FILES.fetch(name) { raise ArgumentError, "unsupported cgroup v2 controller file #{name.inspect}" }
            write_file(File.join(target, name), encode_limit(file, value))
          end
          true
        end

        # Reverse-order release of directories created by an unfinished
        # create.  Cleanup errors are attached to the original failure and
        # never replace it (§5.8.4).
        def rollback_created(created, error)
          cleanup_errors = []
          created.reverse_each do |directory|
            begin
              @adapter.delete(directory) if @adapter.directory?(directory)
            rescue SystemCallError => cleanup_error
              cleanup_errors << "#{directory}: #{cleanup_error.class}: #{cleanup_error.message}"
            end
          end
          return if cleanup_errors.empty?

          existing = error.respond_to?(:cleanup_errors) ? Array(error.cleanup_errors) : []
          error.instance_variable_set(:@cgroup_cleanup_errors, (existing + cleanup_errors).freeze)
          error.define_singleton_method(:cleanup_errors) { @cgroup_cleanup_errors } unless error.respond_to?(:cleanup_errors)
        rescue StandardError
          # A frozen exception cannot carry cleanup details; the primary error
          # remains authoritative and the rollback effects were still attempted.
          nil
        end

        def freeze_root
          @root = @root.dup.freeze
        end

        def normalize_qos(value)
          qos = String(value).downcase
          raise InvalidPath, "qos must be one of #{QOS_CLASSES.join(", ")}" unless QOS_CLASSES.include?(qos)

          qos
        end

        def validate_component(value, name)
          component = String(value)
          unless component.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
            raise InvalidPath, "#{name} must be a single safe cgroup path component"
          end

          component
        end

        def handle_path(handle)
          value = handle.respond_to?(:path) ? handle.path : handle
          target = File.expand_path(String(value))
          prefix = File.join(@root, @hierarchy) + File::SEPARATOR
          raise InvalidPath, "cgroup path escapes configured hierarchy" unless target.start_with?(prefix)

          target
        end

        def normalize_limits(limits)
          unless limits.respond_to?(:to_h)
            raise ArgumentError, "cgroup limits must be a hash"
          end

          limits.to_h.each_with_object({}) do |(key, value), normalized|
            name = String(key)
            name = name.tr("_", ".") if CONTROLLER_FILES.key?(name.tr("_", "."))
            normalized[name] = value
          end
        end

        def encode_limit(file, value)
          case file
          when :cpu_max
            values = value.is_a?(Array) ? value : String(value).split
            raise ArgumentError, "cpu.max requires quota and period" unless values.length == 2

            quota, period = values.map { |item| validate_limit_token(item) }
            "#{quota} #{period}"
          when :io_max
            String(value).strip.tap { |encoded| raise ArgumentError, "io.max must not be empty" if encoded.empty? }
          when :cpu_weight
            weight = Integer(String(value).strip)
            # Documentation/admin-guide/cgroup-v2.rst: cpu.weight is [1, 10000].
            raise ArgumentError, "cpu.weight must be between 1 and 10000" unless weight.between?(1, 10_000)

            weight.to_s
          when :memory_oom_group
            token = String(value).strip
            raise ArgumentError, "memory.oom.group must be 0 or 1" unless %w[0 1].include?(token)

            token
          when :cpuset_cpus, :cpuset_mems
            token = String(value).strip
            raise ArgumentError, "cpuset list must be a comma separated list of ranges" unless token.match?(/\A(?:[0-9]+(?:-[0-9]+)?)(?:,[0-9]+(?:-[0-9]+)?)*\z/) || token.empty?

            token
          else
            validate_limit_token(value)
          end
        end

        def validate_limit_token(value)
          token = String(value).strip
          raise ArgumentError, "cgroup limit must be a non-negative integer or max" unless token.match?(/\A(?:max|[0-9]+)\z/)

          token
        end

        def read_words(path)
          return [] unless @adapter.exists?(path)

          read_file(path).split.map(&:freeze)
        end

        def read_file(path)
          String(@adapter.read(path))
        rescue SystemCallError => error
          raise Error, "failed to read cgroup file #{path}: #{error.message}"
        end

        def write_file(path, value)
          @adapter.write(path, String(value))
        rescue SystemCallError => error
          raise Error, "failed to write cgroup file #{path}: #{error.message}"
        end

        def parse_scalar(value)
          token = String(value).strip
          Integer(token)
        rescue ArgumentError
          raise Error, "invalid cgroup scalar #{token.inspect}"
        end

        def parse_key_values(value)
          String(value).lines.each_with_object({}) do |line, values|
            tokens = line.split
            next if tokens.empty?

            key = tokens.shift
            values[key] = if tokens.empty?
              0
            elsif tokens.length == 1 && tokens.first.match?(/\A-?[0-9]+\z/)
              Integer(tokens.first)
            else
              tokens.map { |token| token.match?(/\A-?[0-9]+\z/) ? Integer(token) : token }
            end
          end
        end
      end
    end
  end
end
