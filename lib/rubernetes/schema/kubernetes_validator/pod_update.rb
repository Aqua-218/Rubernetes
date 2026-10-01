# frozen_string_literal: true

require "json"
require_relative "../quantity"

module Rubernetes
  module Schema
    # ValidatePodUpdate (pkg/apis/core/validation/validation.go, v1.36.2): the
    # spec rules of a Pod update -- containers neither added nor removed,
    # activeDeadlineSeconds only lowered, tolerations only added, scheduling
    # gates only removed, a gated Pod's node selector and required node
    # affinity only extended -- and the refusal of any other spec change,
    # worded with diff.Diff of the internal core.PodSpec before and after.
    module KubernetesValidator
      # github.com/pmezard/go-difflib (the diff apimachinery's util/diff
      # uses): SequenceMatcher with its autojunk heuristic and the unified
      # diff writer, without file headers.
      module GoDiffLib
        module_function

        # difflib.SplitLines.
        def split_lines(text)
          lines = text.split(/(?<=\n)/, -1)
          lines = [""] if lines.empty?
          lines[-1] += "\n"
          lines
        end

        def unified_diff(a, b, context: 3)
          matcher = SequenceMatcher.new(a, b)
          out = +""
          matcher.grouped_opcodes(context).each do |group|
            first = group.first
            last = group.last
            out << "@@ -#{format_range(first[1], last[2])} +#{format_range(first[3], last[4])} @@\n"
            group.each do |tag, i1, i2, j1, j2|
              if tag == :equal
                a[i1...i2].each { |line| out << " " << line }
                next
              end
              a[i1...i2].each { |line| out << "-" << line } if %i[replace delete].include?(tag)
              b[j1...j2].each { |line| out << "+" << line } if %i[replace insert].include?(tag)
            end
          end
          out
        end

        def format_range(start, stop)
          beginning = start + 1
          length = stop - start
          return beginning.to_s if length == 1

          beginning -= 1 if length.zero?
          "#{beginning},#{length}"
        end

        class SequenceMatcher
          def initialize(a, b)
            @a = a
            @b = b
            chain_b
          end

          def chain_b
            @b2j = {}
            @b.each_with_index { |line, index| (@b2j[line] ||= []) << index }
            n = @b.length
            return unless n >= 200

            ntest = (n / 100) + 1
            @b2j.delete_if { |_line, indices| indices.length > ntest }
          end

          # No IsJunk function is given, so no element of b is junk; the
          # popular ones are only left out of b2j.
          def find_longest_match(alo, ahi, blo, bhi)
            besti = alo
            bestj = blo
            bestsize = 0
            j2len = {}
            (alo...ahi).each do |i|
              newj2len = {}
              (@b2j[@a[i]] || []).each do |j|
                next if j < blo
                break if j >= bhi

                k = j2len.fetch(j - 1, 0) + 1
                newj2len[j] = k
                next unless k > bestsize

                besti = i - k + 1
                bestj = j - k + 1
                bestsize = k
              end
              j2len = newj2len
            end
            while besti > alo && bestj > blo && @a[besti - 1] == @b[bestj - 1]
              besti -= 1
              bestj -= 1
              bestsize += 1
            end
            bestsize += 1 while besti + bestsize < ahi && bestj + bestsize < bhi && @a[besti + bestsize] == @b[bestj + bestsize]
            [besti, bestj, bestsize]
          end

          def matching_blocks
            @matching_blocks ||= begin
              matched = []
              queue = [[0, @a.length, 0, @b.length]]
              # matchBlocks recursion, in the same (left, match, right) order.
              visit = lambda do |alo, ahi, blo, bhi|
                i, j, k = find_longest_match(alo, ahi, blo, bhi)
                next if k.zero?

                visit.call(alo, i, blo, j) if alo < i && blo < j
                matched << [i, j, k]
                visit.call(i + k, ahi, j + k, bhi) if i + k < ahi && j + k < bhi
              end
              queue.each { |bounds| visit.call(*bounds) }
              blocks = []
              i1 = j1 = k1 = 0
              matched.each do |i2, j2, k2|
                if i1 + k1 == i2 && j1 + k1 == j2
                  k1 += k2
                else
                  blocks << [i1, j1, k1] if k1.positive?
                  i1 = i2
                  j1 = j2
                  k1 = k2
                end
              end
              blocks << [i1, j1, k1] if k1.positive?
              blocks << [@a.length, @b.length, 0]
            end
          end

          def opcodes
            i = j = 0
            codes = []
            matching_blocks.each do |ai, bj, size|
              tag = if i < ai && j < bj then :replace
                    elsif i < ai then :delete
                    elsif j < bj then :insert
                    end
              codes << [tag, i, ai, j, bj] if tag
              i = ai + size
              j = bj + size
              codes << [:equal, ai, i, bj, j] if size.positive?
            end
            codes
          end

          def grouped_opcodes(n)
            codes = opcodes
            codes = [[:equal, 0, 1, 0, 1]] if codes.empty?
            if codes.first[0] == :equal
              _, i1, i2, j1, j2 = codes.first
              codes[0] = [:equal, [i1, i2 - n].max, i2, [j1, j2 - n].max, j2]
            end
            if codes.last[0] == :equal
              _, i1, i2, j1, j2 = codes.last
              codes[-1] = [:equal, i1, [i2, i1 + n].min, j1, [j2, j1 + n].min]
            end
            nn = n + n
            groups = []
            group = []
            codes.each do |tag, i1, i2, j1, j2|
              if tag == :equal && i2 - i1 > nn
                group << [tag, i1, [i2, i1 + n].min, j1, [j2, j1 + n].min]
                groups << group
                group = []
                i1 = [i1, i2 - n].max
                j1 = [j1, j2 - n].max
              end
              group << [tag, i1, i2, j1, j2]
            end
            groups << group if group.any? && !(group.length == 1 && group.first[0] == :equal)
            groups
          end
        end
      end

      # The internal core.PodSpec a v1 Pod converts to (conversion-gen plus
      # the manual Convert_v1_PodSpec_To_core_PodSpec and
      # Convert_v1_Pod_To_core_Pod), rendered the way encoding/json's
      # MarshalIndent(spec, "", " ") prints it.  The field layout is
      # schema/kubernetes/v1.36.2-defaults/internal_pod_spec_layout.json
      # (tools/schema/import_internal_pod_spec.rb).
      module InternalPodSpec
        LAYOUT_PATH = File.expand_path("../../../../schema/kubernetes/v1.36.2-defaults/internal_pod_spec_layout.json", __dir__)
        CORE = "k8s.io/kubernetes/pkg/apis/core."
        HOST_FIELDS = {"HostNetwork" => "hostNetwork", "HostPID" => "hostPID", "HostIPC" => "hostIPC",
                       "ShareProcessNamespace" => "shareProcessNamespace", "HostUsers" => "hostUsers"}.freeze

        # An internal struct value: its fields in declaration order, each
        # [key the encoder prints, Go name, value], omitempty ones left out.
        Struct = Data.define(:type, :fields) do
          def [](go_name) = fields.find { |_key, go, _value| go == go_name }&.last

          def with(go_name, value)
            self.class.new(type: type, fields: fields.map { |key, go, old| go == go_name ? [key, go, value] : [key, go, old] })
          end
        end

        module_function

        def layout
          @layout ||= JSON.parse(File.read(LAYOUT_PATH))
        end

        # The internal spec of a v1 Pod.  Storage hands the old object back
        # through protobuf, where an empty list or map reads as nil; a
        # request body decoded from JSON keeps them (keep_empty).
        def convert(pod, keep_empty: false)
          v1 = pod.is_a?(Hash) ? (pod["spec"] || {}) : {}
          spec = convert_struct(layout.fetch("internal"), v1, keep_empty)
          # Convert_v1_PodSpec_To_core_PodSpec.
          spec = spec.with("ServiceAccountName", v1["serviceAccount"].to_s) if v1["serviceAccountName"].to_s.empty?
          context = spec["SecurityContext"] || zero_struct(CORE + "PodSecurityContext")
          HOST_FIELDS.each do |go, key|
            value = v1[key]
            value = value == true if %w[HostNetwork HostPID HostIPC].include?(go)
            context = context.with(go, value)
          end
          spec = spec.with("SecurityContext", context)
          # Convert_v1_Pod_To_core_Pod.
          grace = v1["terminationGracePeriodSeconds"]
          spec = spec.with("TerminationGracePeriodSeconds", 1) if grace.is_a?(Integer) && grace.negative?
          spec
        end

        def convert_value(type, value, keep_empty = false)
          case type["k"]
          when "string" then value.is_a?(String) ? value : ""
          when "int", "uint" then value.is_a?(Numeric) ? value.to_i : 0
          when "float" then value.is_a?(Numeric) ? value.to_f : 0.0
          when "bool" then value == true
          when "ptr" then value.nil? ? nil : convert_value(type["e"], value, keep_empty)
          when "slice"
            return nil unless value.is_a?(Array) && (keep_empty || !value.empty?)

            value.map { |item| convert_value(type["e"], item, keep_empty) }
          when "map"
            return nil unless value.is_a?(Hash) && (keep_empty || !value.empty?)

            value.keys.map(&:to_s).sort.to_h { |key| [key, convert_value(type["e"], value[key], keep_empty)] }
          when "bytes" then value.is_a?(String) && (keep_empty || !value.empty?) ? value : nil
          when "struct" then convert_struct(type["n"], value.is_a?(Hash) ? value : {}, keep_empty)
          when "quantity" then value.nil? ? "0" : Quantity.from_json(value).to_s
          when "intorstring" then value.is_a?(Integer) || value.is_a?(String) ? value : 0
          when "time" then value.is_a?(String) && !value.empty? ? value : nil
          when "fieldsv1" then value
          else raise ArgumentError, "unknown layout type #{type["k"]}"
          end
        end

        def convert_struct(name, v1, keep_empty = false)
          fields = layout.fetch("types").fetch(name).filter_map do |field|
            source = field["v1"] ? v1.dig(*field["v1"]) : nil
            value = convert_value(field["type"], source, keep_empty)
            next if field["omitempty"] && empty_value?(value)

            [field["key"], field["go"], value]
          end
          Struct.new(type: name, fields: fields)
        end

        def zero_struct(name) = convert_struct(name, {})

        # apiequality.Semantic.DeepEqual's view: nil and empty lists, maps
        # and byte slices are equal.
        def semantic(value)
          case value
          when Struct then Struct.new(type: value.type, fields: value.fields.map { |key, go, item| [key, go, semantic(item)] })
          when Array then value.empty? ? nil : value.map { |item| semantic(item) }
          when Hash then value.empty? ? nil : value.transform_values { |item| semantic(item) }
          else value
          end
        end

        def empty_value?(value)
          value.nil? || value == false || value == 0 || value == "" || (value.is_a?(Array) && value.empty?) || (value.is_a?(Hash) && value.empty?)
        end

        # json.MarshalIndent(value, "", " ").
        def render(value, depth = 0)
          case value
          when nil then "null"
          when true, false, Integer then value.to_s
          when Float then go_float(value)
          when String then go_string(value)
          when Struct
            members = value.fields.map { |key, _go, item| [key, item] }
            render_object(members, depth)
          when Hash then render_object(value.to_a, depth)
          when Array
            return "[]" if value.empty?

            inner = " " * (depth + 1)
            "[\n#{value.map { |item| inner + render(item, depth + 1) }.join(",\n")}\n#{" " * depth}]"
          else raise ArgumentError, "cannot render #{value.class}"
          end
        end

        def render_object(members, depth)
          return "{}" if members.empty?

          inner = " " * (depth + 1)
          "{\n#{members.map { |key, item| "#{inner}#{go_string(key.to_s)}: #{render(item, depth + 1)}" }.join(",\n")}\n#{" " * depth}}"
        end

        # encoding/json string escaping (HTML-safe, \b and \f short forms).
        def go_string(text)
          text = text.to_s.dup.force_encoding(Encoding::UTF_8)
          text = text.scrub("�") unless text.valid_encoding?
          out = +"\""
          text.each_char do |char|
            out << case char
                   when "\\" then "\\\\"
                   when "\"" then "\\\""
                   when "\n" then "\\n"
                   when "\r" then "\\r"
                   when "\t" then "\\t"
                   when "\b" then "\\b"
                   when "\f" then "\\f"
                   when "<", ">", "&", " ", " " then format("\\u%04x", char.ord)
                   else char.ord < 0x20 ? format("\\u%04x", char.ord) : char
                   end
          end
          out << "\""
        end

        # encoding/json floatEncoder for float64.
        def go_float(value)
          return value.to_i.to_s if (value == value.floor && value.abs < 1e21 && value.abs >= 1e-6) || value.zero?

          if value.abs < 1e-6 || value.abs >= 1e21
            mantissa, exponent = format("%.17g", value).then { |s| Float(s) }.to_s.split("e")
            exponent ||= "0"
            "#{mantissa.delete_suffix(".0")}e#{exponent.to_i.negative? ? "-" : "+"}#{exponent.to_i.abs.to_s.rjust(2, "0")}"
          else
            value.to_s
          end
        end

        # json.Marshal(value): what field.Error prints for a value that is not
        # a string, bool or number.
        def compact(value)
          case value
          when Struct then "{#{value.fields.map { |key, _go, item| "#{go_string(key.to_s)}:#{compact(item)}" }.join(",")}}"
          when Hash then "{#{value.map { |key, item| "#{go_string(key.to_s)}:#{compact(item)}" }.join(",")}}"
          when Array then "[#{value.map { |item| compact(item) }.join(",")}]"
          else render(value)
          end
        end
      end

      UPDATABLE_POD_SPEC_FIELDS = [
        "`spec.containers[*].image`",
        "`spec.initContainers[*].image`",
        "`spec.activeDeadlineSeconds`",
        "`spec.tolerations` (only additions to existing tolerations)",
        "`spec.terminationGracePeriodSeconds` (allow it to be set to 1 if it was previously negative)"
      ].freeze
      MAX_INT32 = (2**31) - 1

      module_function

      def pod_update_errors(root, kind, operation, old = nil)
        return [] unless kind == "Pod" && operation == :update

        unless old.is_a?(Hash)
          containers = fetch(fetch(root, "spec"), "containers")
          return containers.is_a?(Array) && containers.first.is_a?(Hash) && blank?(fetch(containers.first,
                                                                                         "image")) ? [issue(%w[spec containers 0 image],
                                                                                                            :required, "")] : []
        end
        new_spec = InternalPodSpec.convert(root, keep_empty: true)
        old_spec = InternalPodSpec.convert(old)
        issues = []
        %w[Containers containers InitContainers initContainers].each_slice(2) do |go, key|
          container_issues, stop = container_update_errors(Array(new_spec[go]), Array(old_spec[go]), ["spec", key])
          issues.concat(container_issues)
          return issues if stop
        end
        deadline = new_spec["ActiveDeadlineSeconds"]
        old_deadline = old_spec["ActiveDeadlineSeconds"]
        if !deadline.nil?
          if deadline.negative? || deadline > MAX_INT32
            return issues << ValidationIssue.new(path: %w[spec activeDeadlineSeconds], code: :invalid, value: deadline,
                                                 message: "must be between 0 and #{MAX_INT32}, inclusive", kubernetes_type: "Invalid value")
          end
          if !old_deadline.nil? && old_deadline < deadline
            return issues << ValidationIssue.new(path: %w[spec activeDeadlineSeconds], code: :invalid, value: deadline,
                                                 message: "must be less than or equal to previous value", kubernetes_type: "Invalid value")
          end
        elsif !old_deadline.nil?
          issues << ValidationIssue.new(path: %w[spec activeDeadlineSeconds], code: :invalid, value: go_value("null"),
                                        message: "must not update from a positive integer to nil value", kubernetes_type: "Invalid value")
        end
        issues.concat(only_added_toleration_errors(Array(new_spec["Tolerations"]), Array(old_spec["Tolerations"])))
        issues.concat(only_deleted_scheduling_gate_errors(Array(new_spec["SchedulingGates"]), Array(old_spec["SchedulingGates"])))
        return issues if InternalPodSpec.semantic(new_spec) == InternalPodSpec.semantic(old_spec)

        munged, gated_issues = munge_pod_spec(new_spec, old_spec)
        issues.concat(gated_issues)
        return issues if InternalPodSpec.semantic(munged) == InternalPodSpec.semantic(old_spec)

        old_text = InternalPodSpec.render(old_spec)
        new_text = InternalPodSpec.render(munged)
        spec_diff = GoDiffLib.unified_diff(GoDiffLib.split_lines(old_text), GoDiffLib.split_lines(new_text))
        issues << issue(%w[spec], :forbidden,
                        "pod updates may not change fields other than #{UPDATABLE_POD_SPEC_FIELDS.join(",")}\n#{spec_diff}")
      end

      # ValidateContainerUpdates.
      def container_update_errors(new_containers, old_containers, path)
        if new_containers.length != old_containers.length
          return [[issue(path, :forbidden, "pod updates may not add or remove containers")],
                  true]
        end

        issues = []
        new_containers.each_with_index do |container, index|
          image = container["Image"].to_s
          issues << issue(path + [index.to_s, "image"], :required, "") if image.empty?
          next if image.strip.length == image.length

          issues << ValidationIssue.new(path: path + [index.to_s, "image"], code: :invalid, value: image,
                                        message: "must not have leading or trailing whitespace", kubernetes_type: "Invalid value")
        end
        [issues, false]
      end

      # validateOnlyAddedTolerations (ValidateTolerations of the new list runs
      # with the pod spec validation).
      def only_added_toleration_errors(new_tolerations, old_tolerations)
        old_tolerations.each do |old|
          found = new_tolerations.any? { |candidate| old.with("TolerationSeconds", candidate["TolerationSeconds"]) == candidate }
          unless found
            return [issue(%w[spec tolerations], :forbidden,
                          "existing toleration can not be modified except its tolerationSeconds")]
          end
        end
        []
      end

      # validateOnlyDeletedSchedulingGates: one error per gate the old list
      # lacks, in Go map iteration order upstream (random; index order here).
      def only_deleted_scheduling_gate_errors(new_gates, old_gates)
        return [] if new_gates.empty?

        added = {}
        new_gates.each_with_index { |gate, index| added[gate["Name"]] = index }
        old_gates.each { |gate| added.delete(gate["Name"]) }
        added.sort_by { |_name, index| index }.map do |name, index|
          issue(["spec", "schedulingGates", index.to_s, "name"], :forbidden,
                "only deletion is allowed, but found new scheduling gate '#{name}'")
        end
      end

      # The updatable fields taken from the old spec, and a gated Pod's node
      # selector and required node affinity checked for additions only.
      def munge_pod_spec(new_spec, old_spec)
        munged = new_spec
        %w[Containers InitContainers].each do |go|
          containers = munged[go]
          next munged = munged.with(go, nil) if containers.nil? || containers.empty?

          munged = munged.with(go, containers.each_with_index.map do |container, index|
            container.with("Image", old_spec[go][index]["Image"])
          end)
        end
        munged = munged.with("ActiveDeadlineSeconds", old_spec["ActiveDeadlineSeconds"])
          .with("SchedulingGates", old_spec["SchedulingGates"])
          .with("Tolerations", old_spec["Tolerations"])
        old_grace = old_spec["TerminationGracePeriodSeconds"]
        if !old_grace.nil? && old_grace.negative? && munged["TerminationGracePeriodSeconds"] == 1
          munged = munged.with("TerminationGracePeriodSeconds", old_grace)
        end
        issues = []
        return [munged, issues] if Array(old_spec["SchedulingGates"]).empty?

        if InternalPodSpec.semantic(munged["NodeSelector"]) != InternalPodSpec.semantic(old_spec["NodeSelector"])
          new_selector = munged["NodeSelector"] || {}
          if (old_spec["NodeSelector"] || {}).any? { |key, value| new_selector[key] != value }
            issues << ValidationIssue.new(path: %w[spec nodeSelector], code: :invalid,
                                          value: go_value(InternalPodSpec.compact(munged["NodeSelector"])),
                                          message: "only additions to spec.nodeSelector are allowed (no mutations or deletions)", kubernetes_type: "Invalid value")
          end
          munged = munged.with("NodeSelector", old_spec["NodeSelector"])
        end
        old_affinity = old_spec["Affinity"]&.[]("NodeAffinity")
        munged_affinity = munged["Affinity"]&.[]("NodeAffinity")
        if InternalPodSpec.semantic(old_affinity) != InternalPodSpec.semantic(munged_affinity)
          issues.concat(node_affinity_mutation_errors(munged_affinity, old_affinity))
          affinity = munged["Affinity"]
          munged = if affinity.nil? && old_affinity.nil?
                     munged
                   elsif affinity.nil?
                     munged.with("Affinity",
                                 InternalPodSpec.zero_struct(InternalPodSpec::CORE + "Affinity").with("NodeAffinity", old_affinity))
                   elsif old_spec["Affinity"].nil? && affinity["PodAntiAffinity"].nil? && affinity["PodAffinity"].nil?
                     munged.with("Affinity", nil)
                   else
                     munged.with("Affinity", affinity.with("NodeAffinity", old_affinity))
                   end
        end
        [munged, issues]
      end

      # A value field.Error prints as is (its json.Marshal rendering).
      GoValue = Data.define(:text) do
        def to_s = text
        def inspect = text
        def to_json(*) = text
      end

      def go_value(text) = GoValue.new(text: text)

      # validateNodeAffinityMutation / validateNodeSelectorTermHasOnlyAdditions.
      def node_affinity_mutation_errors(new_affinity, old_affinity)
        required = old_affinity&.[]("RequiredDuringSchedulingIgnoredDuringExecution")
        return [] if required.nil?

        old_terms = Array(required["NodeSelectorTerms"])
        new_required = new_affinity&.[]("RequiredDuringSchedulingIgnoredDuringExecution")
        new_terms = new_required&.[]("NodeSelectorTerms")
        path = %w[spec affinity nodeAffinity requiredDuringSchedulingIgnoredDuringExecution nodeSelectorTerms]
        if !old_terms.empty? && old_terms.length != Array(new_terms).length
          return [ValidationIssue.new(path: path, code: :invalid, value: go_value(InternalPodSpec.compact(new_terms)),
                                      message: "no additions/deletions to non-empty NodeSelectorTerms list are allowed", kubernetes_type: "Invalid value")]
        end

        old_terms.each_with_index.filter_map do |old_term, index|
          new_term = new_terms[index]
          next if node_selector_term_only_additions?(new_term, old_term)

          ValidationIssue.new(path: path + [index.to_s], code: :invalid, value: go_value(InternalPodSpec.compact(new_term)),
                              message: "only additions are allowed (no mutations or deletions)", kubernetes_type: "Invalid value")
        end
      end

      def node_selector_term_only_additions?(new_term, old_term)
        old_expressions = Array(old_term["MatchExpressions"])
        old_fields = Array(old_term["MatchFields"])
        new_expressions = Array(new_term["MatchExpressions"])
        new_fields = Array(new_term["MatchFields"])
        return false if old_expressions.empty? && old_fields.empty? && (new_expressions.any? || new_fields.any?)
        if old_expressions.any? && (new_expressions.length < old_expressions.length || new_expressions.first(old_expressions.length) != old_expressions)
          return false
        end
        return false if old_fields.any? && (new_fields.length < old_fields.length || new_fields.first(old_fields.length) != old_fields)

        true
      end
    end
  end
end
