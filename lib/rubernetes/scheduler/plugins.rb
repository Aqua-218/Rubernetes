# frozen_string_literal: true

require "set"

module Rubernetes
  module Scheduler
    # A structured filter rejection is kept in traces instead of collapsing all
    # failures to a boolean.  This mirrors the reason-bearing diagnostics of
    # Kubernetes Filter plugins while remaining convenient for custom blocks.
    class Rejection
      attr_reader :reason, :code, :details

      def initialize(reason, code: nil, details: nil)
        reason = reason.to_s
        raise ValidationError, "filter rejection reason cannot be empty" if reason.empty?

        @reason = reason.freeze
        @code = code&.to_s&.freeze
        @details = details.nil? ? nil : Support.snapshot(details)
        freeze
      end

      def accepted?
        false
      end

      def to_h
        result = {"accepted" => false, "reason" => reason}
        result["code"] = code if code
        result["details"] = details if details
        result
      end

      def inspect
        "#<#{self.class.name} #{to_h.inspect}>"
      end
    end

    class FilterResult
      attr_reader :accepted, :reason, :code, :details

      def initialize(accepted:, reason: nil, code: nil, details: nil)
        @accepted = !!accepted
        @reason = reason&.to_s&.freeze
        @code = code&.to_s&.freeze
        @details = details.nil? ? nil : Support.snapshot(details)
        freeze
      end

      def accepted?
        accepted
      end

      def rejected?
        !accepted
      end

      def to_h
        return {"accepted" => true} if accepted

        result = {"accepted" => false, "reason" => reason || "rejected by plugin"}
        result["code"] = code if code
        result["details"] = details if details
        result
      end
    end

    # Immutable registration record.  The block is deliberately not exposed
    # in #to_h so trace output never includes an unstable Ruby object address.
    class Plugin
      # Kubernetes MultiPoint plugins are registered once and expanded by the
      # framework at each extension point.  Keeping the primary phase and the
      # supported phases separate preserves the pinned inventory order while
      # still making every concrete lifecycle method observable.
      PHASES = %i[pre_enqueue queue_sort filter score post_filter reserve unreserve pre_bind bind].freeze

      attr_reader :name, :kind, :phase, :weight, :block, :supported_phases, :score_extension

      # +score_extension+: an object answering score_nodes(pod, nodes, context)
      # with {node name => score} or Scores::SKIP -- upstream's PreScore, Score
      # and NormalizeScore in one call, normalized over the feasible nodes.
      # Without one the block is asked for each node on its own.
      def initialize(name:, kind: nil, phase: nil, weight: 1, block:, supported_phases: nil, score_extension: nil)
        canonical_name = name.to_s
        unless canonical_name.match?(/\A[a-zA-Z][a-zA-Z0-9_.-]*\z/)
          raise ValidationError, "invalid scheduler plugin name #{name.inspect}"
        end
        normalized_kind = kind&.to_sym
        normalized_phase = (phase || normalized_kind)&.to_sym
        raise ValidationError, "unsupported scheduler plugin phase #{normalized_phase.inspect}" unless PHASES.include?(normalized_phase)
        if normalized_kind && normalized_kind != normalized_phase
          raise ValidationError, "plugin kind #{normalized_kind.inspect} conflicts with phase #{normalized_phase.inspect}"
        end
        raise ValidationError, "scheduler plugin block is required" unless block.respond_to?(:call)
        unless block.arity == 2 || block.arity.negative?
          raise ValidationError, "#{canonical_name} must accept pod and node arguments"
        end

        normalized_weight = if weight.is_a?(Integer)
                              weight
                            elsif weight.is_a?(String) && weight.strip.match?(/\A\+?\d+\z/)
                              Integer(weight, 10)
                            else
                              raise ArgumentError
                            end
        raise ValidationError, "#{canonical_name} weight must be a positive integer" unless normalized_weight.positive?

        phases = Array(supported_phases || normalized_phase).map(&:to_sym).uniq
        unless phases.all? { |candidate| PHASES.include?(candidate) }
          raise ValidationError, "#{canonical_name} has an unsupported lifecycle phase"
        end
        unless phases.include?(normalized_phase) || normalized_phase == :multi_point
          raise ValidationError, "#{canonical_name} primary phase must be supported"
        end

        @name = canonical_name.freeze
        @kind = normalized_phase
        @phase = normalized_phase
        @weight = normalized_weight
        @block = block
        @supported_phases = phases.freeze
        @score_extension = score_extension
        freeze
      rescue ArgumentError, TypeError
        raise ValidationError, "#{name} weight must be a positive integer"
      end

      def trace_name
        name
      end

      def filter?
        supports_phase?(:filter)
      end

      def score?
        supports_phase?(:score)
      end

      def pre_enqueue?
        supports_phase?(:pre_enqueue)
      end

      def queue_sort?
        supports_phase?(:queue_sort)
      end

      def post_filter?
        supports_phase?(:post_filter)
      end

      def bind?
        supports_phase?(:bind)
      end

      def supports_phase?(candidate)
        supported_phases.include?(candidate.to_sym)
      end

      def to_h
        {"name" => name, "kind" => kind.to_s, "phase" => phase.to_s,
         "phases" => supported_phases.map(&:to_s), "weight" => weight}.freeze
      end
    end

    class PluginRegistry
      include Enumerable

      def initialize(filters: [], scores: [], plugins: nil)
        @plugins = []
        Array(filters).each { |plugin| register(plugin) }
        Array(scores).each { |plugin| register(plugin) }
        Array(plugins).each { |plugin| register(plugin) }
      end

      # Registrations are mutable only while a DSL is being assembled.  The
      # framework freezes its private copy before any scheduling cycle starts;
      # callers never receive the live backing arrays.
      def filters
        phase_plugins(:filter)
      end

      def scores
        phase_plugins(:score)
      end

      def all
        @plugins.frozen? ? @plugins : @plugins.dup.freeze
      end

      alias plugins all

      def phase_plugins(phase)
        normalized_phase = phase.to_sym
        unless Plugin::PHASES.include?(normalized_phase)
          raise ValidationError, "unsupported scheduler plugin phase #{phase.inspect}"
        end

        selected = @plugins.select { |plugin| plugin.supports_phase?(normalized_phase) }
        selected.frozen? ? selected : selected.freeze
      end

      def find(name, phase: nil)
        normalized_name = name.to_s
        @plugins.find do |plugin|
          plugin.name == normalized_name && (phase.nil? || plugin.supports_phase?(phase))
        end
      end

      def register(plugin)
        raise FrozenError, "scheduler plugin registry is immutable" if frozen?
        unless plugin.is_a?(Plugin)
          raise ValidationError, "scheduler registry accepts Plugin instances"
        end

        index = @plugins.index { |existing| existing.name == plugin.name && existing.phase == plugin.phase }
        if index
          # Kubernetes preserves a default plugin's position when a profile
          # overrides its weight or implementation.
          existing = @plugins[index]
          @plugins[index] = if existing.supported_phases == plugin.supported_phases
                              plugin
                            else
                              Plugin.new(name: plugin.name, kind: existing.kind, phase: existing.phase,
                                         weight: plugin.weight, block: plugin.block,
                                         supported_phases: existing.supported_phases,
                                         score_extension: plugin.score_extension)
                            end
        else
          @plugins << plugin
        end
        self
      end

      def filter(name, phase: :filter, **options, &block)
        register(Plugin.new(name: name, kind: :filter, phase: phase, **options, block: block))
      end

      def score(name, phase: :score, weight: 1, &block)
        register(Plugin.new(name: name, kind: :score, phase: phase, weight: weight, block: block))
      end

      # Queue-sort plugins implement the comparator ABI:
      #   (left_pod, right_pod) -> Integer
      # Negative means left precedes right, zero means equivalent, and
      # positive means right precedes left. The framework normalizes any
      # integer magnitude to -1/0/1 and applies a deterministic identity
      # fallback for equivalent entries.
      def queue_sort(name, weight: 1, &block)
        register(Plugin.new(name: name, kind: :queue_sort, phase: :queue_sort,
                            weight: weight, block: block))
      end

      def merge(other)
        result = self.class.new(plugins: all)
        Array(other&.all || other&.filters).each { |plugin| result.register(plugin) }
        Array(other&.scores).each { |plugin| result.register(plugin) } unless other.respond_to?(:all)
        result
      end

      def dup
        self.class.new(plugins: all)
      end

      def freeze
        @plugins.freeze
        super
      end

      def each(&block)
        return enum_for(__method__) unless block

        all.each(&block)
      end
    end

    # The block context for the scheduler DSL.  It intentionally has a tiny
    # surface: registering a plugin is the only operation custom code can
    # perform during configuration.
    class DSL
      attr_reader :registry

      def initialize(registry = PluginRegistry.new)
        @registry = registry
      end

      def filter(name, **options, &block)
        registry.filter(name, **options, &block)
      end

      def score(name, weight: 1, &block)
        registry.score(name, weight: weight, &block)
      end

      def queue_sort(name, weight: 1, &block)
        registry.queue_sort(name, weight: weight, &block)
      end

      def scheduler(&block)
        instance_eval(&block) if block
        registry
      end
    end

    # The default bind operation is deliberately a pure snapshot transform.
    # The framework's optional bind handler can persist the returned object;
    # without one this class still provides the same Binding target semantics.
    class DefaultBinder
      def call(pod, node, _context = nil)
        bound = Support.deep_copy(pod.to_h)
        bound["spec"] = Support.object_hash(bound["spec"] || {})
        bound["spec"]["nodeName"] = node.name
        Pod.new(bound)
      end

      alias bind call
    end

    # Deterministic, content-addressed cycle trace.  Event order is assigned by
    # the framework at invocation time, so a trace can prove both plugin order
    # and the exact immutable input each plugin observed.
    class Trace
      def initialize
        @events = []
        @mutex = Mutex.new
      end

      def events
        to_a
      end

      # The input digest is taken when the trace is read, from the frozen
      # snapshot of the input the plugin saw.  Hashing every plugin input for
      # every node at invocation time was over a quarter of the scheduler's
      # CPU while nothing in a scheduling cycle reads the trace.
      def record(plugin:, phase:, weight:, input:, output:)
        pending = {
          "order" => nil,
          "plugin" => plugin.to_s,
          "phase" => phase.to_s,
          "weight" => Integer(weight),
          "input" => Support.snapshot(input),
          "output" => Support.snapshot(output)
        }
        @mutex.synchronize do
          pending["order"] = @events.length
          @events << pending
        end
        pending
      end

      def to_a
        @mutex.synchronize do
          @events.map! { |event| event.frozen? ? event : settle(event) }
          @events.dup.freeze
        end
      end

      def settle(event)
        settled = event.reject { |key, _| key == "input" }
        settled["input_snapshot_sha256"] = Support.digest(event.fetch("input"))
        Support.snapshot(settled)
      end

      def to_h
        {"events" => to_a, "sha256" => digest}
      end

      def digest
        Support.digest({"events" => to_a})
      end

      alias trace_digest digest
      alias trace_sha256 digest
    end

    PluginSet = PluginRegistry unless const_defined?(:PluginSet, false)
  end
end
