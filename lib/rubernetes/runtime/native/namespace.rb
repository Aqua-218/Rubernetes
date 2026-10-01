# frozen_string_literal: true

# Namespace planning is kept separate from syscall execution.  The plan is
# pure and deterministic, while the injected adapter owns clone3/unshare/setns
# mechanics and can reject unsupported host flags at the effect boundary.

module Rubernetes
  module Runtime
    class Native
      class Namespace
        class Error < Native::Error; end
        class Unsupported < Error; end
        class InvalidPlan < Error; end

        NAMESPACES = %i[mount pid network uts ipc user cgroup].freeze
        DEFAULT_NAMESPACES = %i[mount pid network uts ipc cgroup].freeze
        HOST_FIELDS = {
          network: :host_network,
          pid: :host_pid,
          ipc: :host_ipc,
          user: :host_users
        }.freeze
        Plan = Data.define(:namespaces, :shared, :host, :user_mapping, :hostname) do
          def to_h
            {
              "namespaces" => namespaces.map(&:to_s),
              "shared" => shared.map(&:to_s),
              "host" => host.map(&:to_s),
              "user_mapping" => user_mapping,
              "hostname" => hostname
            }
          end
        end
        Handle = Data.define(:id, :identity, :plan, :adapter_handle) do
          def to_h
            adapter_identity = if adapter_handle.respond_to?(:to_h)
                                 adapter_handle.to_h
                               else
                                 {"handle" => adapter_handle}
                               end
            {"id" => id, "identity" => identity, "plan" => plan.to_h,
             "kernel_identity" => adapter_identity}
          end
        end

        class RecordingAdapter
          attr_reader :calls

          def initialize
            @calls = []
            @counter = 0
          end

          def create(plan:, id:, identity:)
            @counter += 1
            @calls << [:create, {plan: plan, id: id, identity: identity}]
            "namespace-#{@counter}"
          end

          def destroy(handle:, id:, identity:)
            @calls << [:destroy, {handle: handle, id: id, identity: identity}]
            true
          end
        end

        def initialize(adapter: RecordingAdapter.new, profile: :pure, identity_allocator: nil)
          @adapter = adapter
          @profile = String(profile).downcase.tr("-", "_").to_sym
          @identity_allocator = identity_allocator || ->(id) { "ns:#{id}:#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}" }
          @handles = {}
          @mutex = Mutex.new
        end

        attr_reader :adapter

        # Kubernetes Pod fields (spec.hostNetwork, hostPID, hostIPC, hostUsers,
        # shareProcessNamespace, hostname) are mapped onto the same plan as the
        # runtime's own snake_case keys so Node::Lifecycle can hand the Pod
        # object straight to the runtime.
        POD_FIELDS = {
          "hostNetwork" => :host_network,
          "hostPID" => :host_pid,
          "hostIPC" => :host_ipc,
          "hostUsers" => :host_users,
          "shareProcessNamespace" => :share_process_namespace,
          "hostname" => :hostname
        }.freeze

        def normalize_spec(spec)
          input = spec.respond_to?(:to_h) ? spec.to_h.transform_keys(&:to_s) : {}
          pod_spec = input["spec"]
          if pod_spec.respond_to?(:to_h)
            pod_spec.to_h.each do |key, value|
              field = POD_FIELDS[key.to_s]
              next unless field
              next if input.key?(field.to_s)

              input[field.to_s] = value
            end
          end
          input
        end

        # hostUsers=false is the only input that requests a user namespace;
        # the runtime allocates the UID/GID range before the plan is created.
        def user_namespace_required?(spec)
          input = normalize_spec(spec)
          input.key?("host_users") && input["host_users"] == false
        end

        def plan(spec = {})
          input = normalize_spec(spec)
          host = HOST_FIELDS.each_with_object([]) do |(namespace, field), values|
            values << namespace if truthy?(input, field)
          end
          shared = truthy?(input, :share_process_namespace) ? [:pid] : []
          host_users = if input.key?("host_users")
                         input["host_users"] != false
                       else
                         true
                       end
          # shareProcessNamespace keeps the PID namespace on the holder (the
          # Pod-wide PID 1) and lets every container join it instead of
          # creating a private one.
          namespaces = DEFAULT_NAMESPACES.reject { |name| host.include?(name) }
          namespaces -= [:user] if host_users
          namespaces << :user unless host_users || host.include?(:user)
          user_mapping = host_users ? nil : build_user_mapping(input)
          hostname = input["hostname"] || input["subdomain"]
          Plan.new(namespaces: namespaces.freeze, shared: shared.freeze, host: host.freeze, user_mapping: user_mapping,
                   hostname: hostname && String(hostname).freeze)
        end

        def validate!(plan)
          raise InvalidPlan, "namespace plan must be a Namespace::Plan" unless plan.is_a?(Plan)

          unknown = plan.namespaces - NAMESPACES
          raise InvalidPlan, "unknown namespace #{unknown.first.inspect}" unless unknown.empty?
          raise InvalidPlan, "host and private namespace selections overlap" unless (plan.host & plan.namespaces).empty?
          if plan.shared.include?(:pid) && !plan.namespaces.include?(:pid) && !plan.host.include?(:pid)
            raise InvalidPlan,
                  "a shared PID namespace requires the holder PID namespace"
          end
          raise InvalidPlan, "the user namespace requires a uid/gid mapping" if plan.namespaces.include?(:user) && plan.user_mapping.nil?
          if plan.user_mapping && Integer(plan.user_mapping.fetch(:size) { plan.user_mapping.fetch("size") }) != 65_536
            raise InvalidPlan, "user namespace mapping must allocate exactly 65536 IDs"
          end

          true
        end

        def create(id:, spec: {}, identity: nil)
          plan = spec.is_a?(Plan) ? spec : self.plan(spec)
          validate!(plan)
          if plan.host.any? && !%i[host_integration kernel_isolation l3].include?(@profile)
            raise Unsupported, "host namespace participation requires an explicit host integration profile"
          end

          resource_identity = String(identity || @identity_allocator.call(String(id))).freeze
          adapter_handle = invoke_create(plan, String(id), resource_identity)
          handle = Handle.new(id: String(id).freeze, identity: resource_identity, plan: plan, adapter_handle: adapter_handle)
          @mutex.synchronize { @handles[handle.id] = handle }
          handle
        end

        def destroy(value)
          handle = lookup(value)
          result = if @adapter.respond_to?(:destroy)
                     @adapter.destroy(handle: handle.adapter_handle, id: handle.id, identity: handle.identity)
                   elsif @adapter.respond_to?(:call)
                     @adapter.call(:destroy, handle: handle.adapter_handle, id: handle.id, identity: handle.identity)
                   else
                     raise Unsupported, "namespace adapter cannot destroy resources"
                   end
          # A false adapter response means the holder is still live or its
          # release is otherwise unconfirmed. Keep the handle so a durable
          # cleanup retry can start at this owner again.
          @mutex.synchronize { @handles.delete(handle.id) } unless result == false
          result
        end

        # Reconstruct an adapter-owned namespace handle after durable ledger
        # replay.  The adapter performs the kernel start-time/inode checks;
        # this wrapper only restores the Ruby ownership index.
        def adopt(id:, identity:, plan:, metadata:)
          value = if plan.is_a?(Plan)
                    plan
                  else
                    Plan.new(
                      namespaces: Array(plan.fetch("namespaces")).map(&:to_sym).freeze,
                      shared: Array(plan.fetch("shared", [])).map(&:to_sym).freeze,
                      host: Array(plan.fetch("host", [])).map(&:to_sym).freeze,
                      user_mapping: plan["user_mapping"],
                      hostname: plan["hostname"]
                    )
                  end
          validate!(value)
          adapter_metadata = metadata["kernel_identity"] || metadata[:kernel_identity] || metadata
          adapter_handle = if @adapter.respond_to?(:adopt)
                             @adapter.adopt(id: String(id), identity: String(identity), plan: value, metadata: adapter_metadata)
                           else
                             raise Unsupported, "namespace adapter cannot adopt a live holder"
                           end
          handle = Handle.new(id: String(id).freeze, identity: String(identity).freeze, plan: value,
                              adapter_handle: adapter_handle)
          @mutex.synchronize { @handles[handle.id] = handle }
          handle
        end

        def join(value, namespace:)
          handle = lookup(value)
          name = String(namespace).to_sym
          raise InvalidPlan, "cannot join unknown namespace #{namespace.inspect}" unless NAMESPACES.include?(name)

          raise Unsupported, "namespace adapter cannot join namespaces" unless @adapter.respond_to?(:join)

          @adapter.join(handle: handle.adapter_handle, namespace: name, identity: handle.identity)
        end

        def lookup(value)
          id = value.respond_to?(:id) ? value.id : String(value)
          @mutex.synchronize { @handles.fetch(String(id)) { raise Error, "unknown namespace handle #{id}" } }
        end

        # Returns the namespace handles that this adapter can account for.
        # This is intentionally an adapter-local inventory: it does not infer
        # ownership from the durable ledger and therefore remains useful for
        # startup reconciliation after a journal replay.
        def resources
          @mutex.synchronize { @handles.values.map(&:to_h).freeze }
        end

        alias handles resources

        private

        def invoke_create(plan, id, identity)
          if @adapter.respond_to?(:create)
            @adapter.create(plan: plan, id: id, identity: identity)
          elsif @adapter.respond_to?(:call)
            @adapter.call(:create, plan: plan, id: id, identity: identity)
          else
            raise Unsupported, "namespace adapter cannot create namespaces"
          end
        end

        def truthy?(input, key)
          value = input.key?(key) ? input[key] : input[key.to_s]
          value == true
        end

        def build_user_mapping(input)
          uid_base = Integer(input[:uid_base] || input["uid_base"] || 1_000_000)
          gid_base = Integer(input[:gid_base] || input["gid_base"] || uid_base)
          {
            uid_base: uid_base,
            gid_base: gid_base,
            size: 65_536,
            setgroups: "deny"
          }.freeze
        rescue ArgumentError, TypeError
          raise InvalidPlan, "uid_base and gid_base must be integers"
        end
      end

      NamespaceAdapter = Namespace unless const_defined?(:NamespaceAdapter, false)
    end
  end
end
