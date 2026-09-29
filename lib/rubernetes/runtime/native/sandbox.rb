# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      class Sandbox
        class Error < Native::Error; end

        STATES = %i[new validated image_pinned workspace_allocated isolation_created resources_attached workload_stopped running stopping stopped removed rolling_back cleanup_pending state_unknown].freeze
        TRANSITIONS = {
          new: %i[validated rolling_back state_unknown],
          validated: %i[image_pinned rolling_back state_unknown],
          image_pinned: %i[workspace_allocated rolling_back state_unknown],
          workspace_allocated: %i[isolation_created rolling_back state_unknown],
          isolation_created: %i[resources_attached rolling_back state_unknown],
          resources_attached: %i[workload_stopped rolling_back state_unknown],
          workload_stopped: %i[running rolling_back state_unknown],
          running: %i[stopping state_unknown],
          stopping: %i[stopped rolling_back],
          stopped: %i[removed rolling_back cleanup_pending],
          removed: [],
          rolling_back: %i[stopped cleanup_pending],
          cleanup_pending: %i[rolling_back state_unknown],
          state_unknown: %i[stopping rolling_back cleanup_pending]
        }.freeze
        # A security plan's hash form (the whole seccomp program, ~22 KB) is
        # built once per plan object: container_status asked for it on every
        # status query of every container.
        PLAN_HASHES = ObjectSpace::WeakMap.new
        PLAN_HASHES_MUTEX = Mutex.new

        Container = Data.define(:id, :spec, :state, :process, :security_plan, :cgroup, :created_at, :workspace) do
          def security_plan_hash
            return security_plan unless security_plan.respond_to?(:to_h)

            PLAN_HASHES_MUTEX.synchronize { PLAN_HASHES[security_plan] } ||
              begin
                value = security_plan.to_h.freeze
                PLAN_HASHES_MUTEX.synchronize { PLAN_HASHES[security_plan] = value }
                value
              end
          end

          def to_h
            {
              "id" => id,
              "spec" => spec,
              "state" => state.to_s,
              "process" => process.respond_to?(:to_h) ? process.to_h : process,
              "security_plan" => security_plan_hash,
              "cgroup" => cgroup.respond_to?(:to_h) ? cgroup.to_h : cgroup,
              "workspace" => workspace.respond_to?(:to_h) ? workspace.to_h : workspace,
              "created_at" => created_at&.utc&.iso8601(6)
            }
          end
        end

        attr_reader :id, :identity, :config, :namespace, :workspace, :cgroup, :security_plan

        def initialize(id:, identity:, config:, clock: -> { Time.now.utc })
          @id = String(id).freeze
          @identity = String(identity).freeze
          @config = config
          @clock = clock
          @state = :new
          @namespace = nil
          @workspace = nil
          @cgroup = nil
          @security_plan = nil
          @containers = {}
          # Ids of containers removed before the sandbox itself, so their
          # log directories can be removed with the sandbox by exact name.
          @removed_container_ids = []
          @container_sequence = 0
          @events = []
          @resources_cleaned = false
          @mutex = Mutex.new
        end

        def state
          @mutex.synchronize { @state }
        end

        def transition(to)
          target = String(to).downcase.to_sym
          @mutex.synchronize do
            return @state if target == @state
            unless TRANSITIONS.fetch(@state).include?(target)
              raise Error, "invalid sandbox transition #{@state} -> #{target}"
            end
            @events << {"from" => @state.to_s, "to" => target.to_s, "timestamp" => @clock.call.utc.iso8601(6)}.freeze
            @state = target
          end
        end

        def set_resources(namespace: nil, workspace: nil, cgroup: nil, security_plan: nil)
          @mutex.synchronize do
            @namespace = namespace if namespace
            @workspace = workspace if workspace
            @cgroup = cgroup if cgroup
            @security_plan = security_plan if security_plan
          end
          self
        end

        # A node-unique container id that is never reused.  A restarted
        # container that took the removed one's id also took its create-request
        # identity in the native request ledger, which answered the retry with
        # the container that had just been removed -- so every restart failed
        # with "unknown container" and the Pod stayed in CrashLoopBackOff for
        # ever.  The sequence only ever moves forward.
        def next_container_id
          @mutex.synchronize { "#{@id}.container-#{@container_sequence += 1}" }
        end

        def create_container(spec:, id: nil)
          input = spec.respond_to?(:to_h) ? spec.to_h : {}
          # Numbered from a sequence, never from the live count: a restarted
          # container that took "container-1" again matched the original
          # create request in the native ledger and was answered with the
          # removed container -- every restart failed with "unknown container".
          container_id = String(id || input[:id] || input["id"] || next_container_id)
          raise Error, "container id is invalid" unless container_id.match?(/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z/)
          container = Container.new(id: container_id.freeze, spec: immutable(input), state: :created, process: nil,
                                    security_plan: nil, cgroup: nil, created_at: @clock.call.utc, workspace: nil)
          @mutex.synchronize do
            raise Error, "container #{container_id} already exists" if @containers.key?(container_id)

            @containers[container_id] = container
          end
          container
        end

        def container(value)
          id = value.respond_to?(:id) ? value.id : String(value)
          @mutex.synchronize { @containers.fetch(String(id)) { raise Error, "unknown container #{id}" } }
        end

        def container_if_present(value)
          id = value.respond_to?(:id) ? value.id : String(value)
          @mutex.synchronize { @containers[String(id)] }
        end

        # A pod-level resize changes the Pod spec the sandbox was created with.
        def update_config(config)
          @mutex.synchronize { @config = config }
        end

        def update_container(value, **changes)
          current = container(value)
          next_container = current.with(**changes)
          @mutex.synchronize { @containers[current.id] = next_container }
          next_container
        end

        def remove_container(value)
          current = container(value)
          raise Error, "cannot remove running container #{current.id}" if current.state == :running

          @mutex.synchronize do
            @containers.delete(current.id)
            @removed_container_ids << current.id
          end
          true
        end

        # Every container id this sandbox ever held (live and removed).
        def container_ids_ever
          @mutex.synchronize { (@removed_container_ids + @containers.keys).uniq.freeze }
        end

        def containers
          @mutex.synchronize { @containers.values.map(&:to_h).freeze }
        end

        def events
          @mutex.synchronize { @events.map(&:dup).freeze }
        end

        def resources_cleaned?
          @mutex.synchronize { @resources_cleaned }
        end

        def mark_resources_cleaned
          @mutex.synchronize { @resources_cleaned = true }
          self
        end

        def to_h
          {
            "id" => id,
            "identity" => identity,
            "state" => state.to_s,
            "namespace" => namespace.respond_to?(:to_h) ? namespace.to_h : namespace,
            "workspace" => workspace.respond_to?(:to_h) ? workspace.to_h : workspace,
            "cgroup" => cgroup.respond_to?(:to_h) ? cgroup.to_h : cgroup,
            "containers" => containers,
            "events" => events
          }
        end

        # Return the private network namespace descriptor consumed by the
        # node network lifecycle. The namespace holder, rather than a
        # workload PID, is the stable lifetime owner. A path is included for
        # setns-capable adapters while the inode is checked before the
        # descriptor is handed to a kernel mutation.
        def network_sandbox_context
          result = {"sandbox_id" => id}
          return result.freeze unless namespace

          descriptor = namespace.respond_to?(:to_h) ? namespace.to_h : {}
          kernel = descriptor["kernel_identity"] || descriptor[:kernel_identity] || {}
          kernel = kernel.to_h if kernel.respond_to?(:to_h)
          namespaces = kernel["namespace_links"] || kernel[:namespace_links] || {}
          link = namespaces["network"] || namespaces[:network]
          return result.freeze unless link

          pid = kernel["pid"] || kernel[:pid]
          raise Error, "network namespace holder PID is unavailable" if pid.nil?

          inode = String(link)[/\[(\d+)\]/, 1]
          raise Error, "network namespace inode is unavailable" if inode.nil?

          path = "/proc/#{Integer(pid)}/ns/net"
          actual_inode = File.stat(path).ino
          unless actual_inode == Integer(inode)
            raise Error, "network namespace holder identity changed"
          end

          result["netns"] = {
            "handle" => descriptor["identity"] || descriptor[:identity],
            "path" => path,
            "inode" => actual_inode,
            "pid" => Integer(pid),
            "pidfd" => kernel["pidfd"] || kernel[:pidfd],
            "start_time" => kernel["start_time"] || kernel[:start_time]
          }.compact.freeze
          result.freeze
        rescue ArgumentError, TypeError, SystemCallError => error
          raise Error, "network namespace descriptor is unavailable: #{error.message}"
        end

        private

        def immutable(value)
          copied = case value
          when Hash then value.to_h { |key, child| [String(key), immutable(child)] }
          when Array then value.map { |child| immutable(child) }
          else value
          end
          copied.freeze
        end
      end
    end
  end
end
