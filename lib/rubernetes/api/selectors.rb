# frozen_string_literal: true

module Rubernetes
  module API
    # Kubernetes label and field selector evaluation for list/watch/delete.
    class Selector
      class Error < Status::BadRequest
        def initialize(message, field: nil)
          causes = if field
                     [{"reason" => "FieldValueInvalid", "message" => message.to_s, "field" => field.to_s}]
                   end
          super(message, details: causes && {"causes" => causes})
        end
      end

      Requirement = Struct.new(:key, :operator, :values, keyword_init: true) do
        def initialize(key:, operator:, values: [])
          super(key: key.to_s, operator: operator.to_sym, values: Array(values).map(&:to_s).freeze)
          freeze
        end

        def matches?(value, present: true)
          value = value.to_s unless value.nil?
          case operator
          when :exists
            present
          when :not_exists
            !present
          when :equals
            present && value == values.first
          when :not_equals
            !present || value != values.first
          when :in
            present && values.include?(value)
          when :not_in
            !present || !values.include?(value)
          else
            false
          end
        end
      end

      attr_reader :requirements

      def initialize(requirements = [])
        @requirements = Array(requirements).freeze
        freeze
      end

      # skip_empty_terms: fields.ParseSelector drops empty terms (client-go's
      # fields.AndSelectors with an empty base yields ",type!=helm.sh/release.v1",
      # which is how ingress-nginx lists Secrets); labels.Parse rejects them.
      def self.parse(selector, skip_empty_terms: false)
        # An already-parsed selector is used as it is: parsing its inspect()
        # string produced a requirement nothing could ever match.
        return selector if selector.is_a?(self)
        return new if selector.nil? || selector.to_s.strip.empty?
        parts = split_requirements(selector.to_s)
        parts = parts.reject(&:empty?) if skip_empty_terms
        new(parts.map { |part| parse_requirement(part) })
      end

      def matches?(object)
        requirements.all? do |requirement|
          value, present = fetch(object, requirement.key)
          requirement.matches?(value, present: present)
        end
      end

      alias match? matches?

      def empty?
        requirements.empty?
      end

      # Label keys legitimately contain dots ("app.kubernetes.io/name"), so an
      # exact key wins before the dotted path is walked for field selectors.
      # Field selectors kube-apiserver maps onto nested fields
      # (pkg/apis/core/v1/conversion.go): Event `source` is `source.component`.
      #
      # These are CANDIDATE LISTS, not single paths, because the selectable
      # field is computed from the internal object, which both group-versions
      # convert into.  pkg/registry/core/event/strategy.go#ToSelectableFields:
      #
      #   source := event.Source.Component
      #   if source == "" { source = event.ReportingController }
      #   "reportingComponent": event.ReportingController
      #
      # An Event written through events.k8s.io/v1 carries reportingController
      # and (at most) deprecatedSource, so selecting on `source` has to fall
      # back to it -- otherwise `--field-selector source=test-controller`
      # silently matches nothing for every Event the events.k8s.io API wrote.
      #
      # The events.k8s.io/v1 spellings are here for the same reason, from
      # pkg/apis/events/v1/conversion.go AddFieldLabelConversionsForEvent: that
      # API's clients select on `regarding.*` and `reportingController`, which
      # the apiserver maps onto the core selectable fields before matching.
      EVENT_REGARDING_FIELDS = %w[kind namespace name uid apiVersion resourceVersion fieldPath].freeze

      FIELD_ALIASES = {
        "Event" => {
          "source" => ["source.component", "deprecatedSource.component", "reportingComponent",
                       "reportingController"],
          "reportingComponent" => ["reportingComponent", "reportingController"],
          "reportingController" => ["reportingController", "reportingComponent"]
        }.merge(
          EVENT_REGARDING_FIELDS.to_h do |field|
            ["regarding.#{field}", ["regarding.#{field}", "involvedObject.#{field}"]]
          end
        ).freeze
      }.freeze

      # kube-apiserver converts the *internal* object before matching, where
      # every selectable field exists and an unset one holds its zero value.
      # JSON omits those fields, so an absent selectable field must still
      # match its zero value -- `spec.unschedulable=false` selects every
      # ordinary Node, and `spec.nodeName=""` selects unscheduled Pods.
      FIELD_ZERO_VALUES = {
        "spec.unschedulable" => "false",
        "spec.nodeName" => "",
        "spec.schedulerName" => "",
        "spec.serviceAccountName" => "",
        "spec.restartPolicy" => "",
        "status.phase" => "",
        "status.podIP" => "",
        "status.nominatedNodeName" => "",
        "involvedObject.namespace" => "",
        "involvedObject.name" => "",
        "involvedObject.kind" => "",
        "involvedObject.uid" => "",
        "involvedObject.fieldPath" => "",
        "involvedObject.apiVersion" => "",
        "involvedObject.resourceVersion" => "",
        "reason" => "",
        "source" => "",
        "reportingComponent" => "",
        "reportingController" => "",
        "regarding.namespace" => "",
        "regarding.name" => "",
        "regarding.kind" => "",
        "regarding.uid" => "",
        "regarding.fieldPath" => "",
        "regarding.apiVersion" => "",
        "regarding.resourceVersion" => "",
        "type" => ""
      }.freeze

      # `aliases` is false while resolving an alias candidate: a candidate list
      # may name the selectable field itself ("reportingComponent"), which
      # would otherwise resolve back into the same list forever.
      def fetch(object, path, aliases: true)
        if object.is_a?(Hash)
          kind = object["kind"] || object[:kind]
          candidates = aliases ? FIELD_ALIASES.dig(kind.to_s, path.to_s) : nil
          return fetch_first_present(object, Array(candidates), path) if candidates
          return [object[path.to_s], true] if object.key?(path.to_s)
          return [object[path.to_sym], true] if object.key?(path.to_sym)
        end
        value = object
        path.to_s.split(".").each do |part|
          return [zero_value(path), zero_value?(path)] unless value.is_a?(Hash)
          key = value.key?(part) ? part : part.to_sym
          return [zero_value(path), zero_value?(path)] unless value.key?(key)

          value = value[key]
        end
        [value, true]
      end

      # The first candidate that is present and non-empty wins, mirroring the
      # upstream fallback chain; when none is set the field still exists and
      # holds its zero value, so `source=` matches an Event with no source.
      def fetch_first_present(object, candidates, path)
        candidates.each do |candidate|
          value, found = fetch(object, candidate, aliases: false)
          next unless found
          next if value.nil? || value.to_s.empty?

          return [value, true]
        end
        [zero_value(path) || "", true]
      end

      def zero_value(path)
        FIELD_ZERO_VALUES[path.to_s]
      end

      def zero_value?(path)
        FIELD_ZERO_VALUES.key?(path.to_s)
      end

      class << self
        private

        def split_requirements(value)
          parts = []
          current = +""
          depth = 0
          value.each_char do |character|
            depth += 1 if character == "("
            depth -= 1 if character == ")"
            raise Error, "selector has an unmatched closing parenthesis" if depth.negative?
            if character == "," && depth.zero?
              parts << current.strip
              current = +""
            else
              current << character
            end
          end
          raise Error, "selector has an unmatched opening parenthesis" unless depth.zero?
          parts << current.strip unless current.strip.empty?
          parts
        end

        def parse_requirement(part)
          raise Error, "selector requirement cannot be empty" if part.empty?
          if (match = part.match(/\A(.+?)\s+(notin|in)\s*\(([^)]*)\)\z/i))
            key = validate_key(match[1].strip, part)
            values = match[3].split(",").map(&:strip).reject(&:empty?)
            raise Error, "set selector #{part.inspect} must contain a value" if values.empty?
            operator = match[2].downcase == "in" ? :in : :not_in
            return Requirement.new(key: key, operator: operator, values: values)
          end
          if (match = part.match(/\A(.+?)\s*(==|=|!=)\s*(.*)\z/))
            key = validate_key(match[1].strip, part)
            # An empty value is legal on both sides of Kubernetes selector
            # syntax: `spec.nodeName=` is how a scheduler lists the Pods no
            # node has accepted yet, and `key=` matches an empty label.
            value = match[3].strip
            operator = match[2] == "!=" ? :not_equals : :equals
            return Requirement.new(key: key, operator: operator, values: [value])
          end
          if part.start_with?("!")
            key = validate_key(part[1..].strip, part)
            return Requirement.new(key: key, operator: :not_exists)
          end

          Requirement.new(key: validate_key(part.strip, part), operator: :exists)
        end

        def validate_key(key, expression)
          raise Error, "selector key cannot be empty" if key.empty?
          if key.match?(/[=!,()\s]/)
            raise Error, "selector key #{key.inspect} is invalid in #{expression.inspect}"
          end

          key
        end

      end
    end

    # A selector pair keeps label and field concerns separate while exposing a
    # single predicate to storage adapters.
    class Selectors
      attr_reader :label, :field

      def initialize(label: nil, field: nil, label_selector: nil, field_selector: nil)
        @label = parse_with_field(label || label_selector, "labelSelector")
        @field = parse_with_field(field || field_selector, "fieldSelector")
        freeze
      end

      def matches?(object)
        label.matches?(labels_from(object)) && field.matches?(object)
      end

      alias match? matches?

      # Kubernetes cannot know an exact remainingItemCount after applying a
      # label or field predicate.  Expose emptiness so list implementations can
      # omit that advisory field for filtered collections.
      def empty?
        label.empty? && field.empty?
      end

      def self.from_query(query)
        query = query || {}
        new(label_selector: query["labelSelector"], field_selector: query["fieldSelector"])
      end

      private

      def parse_with_field(value, field)
        Selector.parse(value, skip_empty_terms: field == "fieldSelector")
      rescue Selector::Error => error
        raise Selector::Error.new(error.message, field: field)
      end

      def labels_from(object)
        metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
        labels = metadata["labels"] || metadata[:labels] || {}
        labels.merge("metadata.name" => metadata["name"] || metadata[:name])
      end
    end

    LabelSelector = Selector
    FieldSelector = Selector
  end
end
