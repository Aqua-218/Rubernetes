# frozen_string_literal: true

require_relative "scheduler_plugins"

module Rubernetes
  module Extension
    class PlacementPreview
      # Reuse the production scheduler's input handling, filter rejection
      # rules and score weighting without running its Reserve or Bind phases.
      class Evaluation < Scheduler::Framework
        def call(incoming, nodes, pods)
          target = Scheduler::Pod.new(incoming)
          nodes = normalize_nodes(nodes)
          context = build_context(nodes, normalize_pods(pods, nodes), nil)
          candidates, verdicts = filter_nodes(target, context.nodes, context, trace: nil)
          [verdicts, score_nodes(target, candidates, context, nil)]
        end
      end

      def self.load(name, path)
        new(Definition.compile(name, File.read(path)), path)
      rescue CompileError => error
        raise Client::UsageError, "#{path}: #{error.message}"
      end

      def initialize(extension, path)
        @name = extension.name
        @path = path
        @locations = extension.scheduler_plugins.to_h do |plugin|
          [[plugin.phase, "#{@name}.#{plugin.name}"], "#{path}:#{plugin.block.source_location.last}"]
        end
        @framework = Evaluation.new(standard_plugins: false, plugins: SchedulerPlugins.registry([extension]))
      end

      def read_snapshot(path)
        list = JSON.parse(File.read(path))
        unless list.is_a?(Hash) && list["kind"] == "List" && list["items"].is_a?(Array)
          raise Client::UsageError, "#{path}: expected a Kubernetes List of Pods and Nodes"
        end

        list.fetch("items")
      rescue JSON::ParserError => error
        raise Client::UsageError, "#{path}: #{error.message}"
      end

      def read_cluster(client)
        {"pods" => "Pod", "nodes" => "Node"}.flat_map do |resource, kind|
          items = []
          query = {"limit" => 500}
          loop do
            page = client.get("/api/v1/#{resource}", query: query)
            page.fetch("items").each { |item| items << item.merge("kind" => kind) }
            cursor = page.dig("metadata", "continue")
            break if cursor.to_s.empty?

            query = query.merge("continue" => cursor)
          end
          items
        end
      end

      def evaluate(reference, items)
        unless items.all? { |item| item.is_a?(Hash) && item["metadata"].is_a?(Hash) }
          raise Client::UsageError, "snapshot items must be Kubernetes objects with metadata"
        end

        pods = items.select { |item| item["kind"] == "Pod" }
        target, *others = pods.select { |pod| [pod.dig("metadata", "namespace") || "default", pod.dig("metadata", "name")].join("/") == reference }
        raise Client::UsageError, "Pod #{reference} is missing from the snapshot" unless target
        raise Client::UsageError, "Pod #{reference} appears more than once" unless others.empty?

        nodes = items.select { |item| item["kind"] == "Node" }
        raise Client::UsageError, "the snapshot contains no Nodes" if nodes.empty?

        # Re-evaluate an already placed Pod as an incoming Pod. Count it
        # neither as a resident of its old node nor as pinned to that node.
        incoming = target.merge("spec" => target.fetch("spec", {}).except("nodeName"))
        @framework.call(incoming, nodes, pods - [target])
      rescue Scheduler::PluginError => error
        location = @locations.fetch([error.phase, error.plugin], @path)
        raise Client::UsageError, "#{location}: #{error.message}"
      end

      def explain(reference, items)
        verdicts, scores = evaluate(reference, items)
        lines = ["#{reference} · #{@name} · #{scores.length}/#{verdicts.length} nodes pass this extension"]
        scores.sort_by { |entry| [-entry.total, entry.node.name] }.each do |entry|
          parts = entry.plugins.map { |plugin| "#{plugin.fetch("plugin")} #{plugin.fetch("score")} × #{plugin.fetch("weight")}" }
          lines << ["  #{entry.node.name}", "pass", "+#{entry.total}", *parts].join("  ")
        end
        verdicts.each do |node, verdict|
          next if verdict["accepted"]

          plugin = verdict.fetch("plugin")
          lines << "  #{node}  rejected  #{plugin}: #{verdict.fetch("reason")}  (#{@locations.fetch([:filter, plugin])})"
        end
        lines
      end

      def compare(previous, reference, items)
        before = previous.outcomes(reference, items)
        after = outcomes(reference, items)
        changed = after.keys.sort.reject { |node| before.fetch(node) == after.fetch(node) }
        lines = ["#{reference} · #{changed.size}/#{after.size} nodes changed"]
        changed.each do |node|
          old = before.fetch(node)
          current = after.fetch(node)
          lines << "  #{node}  #{old.summary} → #{current.summary}"
          if current.rejection
            lines << "    #{location(:filter, current.rejection)}"
          elsif old.rejection
            lines << "    previously rejected at #{previous.location(:filter, old.rejection)}"
          else
            (old.rules.keys | current.rules.keys).each do |rule|
              next if old.rules[rule] == current.rules[rule]

              source = current.rules.key?(rule) ? self : previous
              lines << "    #{rule}  #{old.rules.fetch(rule, "absent")} → #{current.rules.fetch(rule, "absent")}  (#{source.location(:score, rule)})"
            end
          end
        end
        lines
      end

      Outcome = Data.define(:summary, :rules, :rejection)

      protected

      def location(phase, name)
        @locations.fetch([phase, name])
      end

      def outcomes(reference, items)
        verdicts, scores = evaluate(reference, items)
        results = scores.to_h do |entry|
          rules = entry.plugins.to_h { |part| [part.fetch("plugin"), "#{part.fetch("score")} × #{part.fetch("weight")}"] }
          [entry.node.name, Outcome.new("pass +#{entry.total}", rules, nil)]
        end
        verdicts.each do |node, verdict|
          next if verdict["accepted"]

          plugin = verdict.fetch("plugin")
          results[node] = Outcome.new("rejected by #{plugin}: #{verdict.fetch("reason")}", {}, plugin)
        end
        results
      end
    end
  end
end
