# frozen_string_literal: true

require "time"
require_relative "table_printer/columns"
require_relative "table_printer/json_path"
require_relative "../schema/quantity"

module Rubernetes
  module API
    # Server-side printing: converts an object or list into a
    # `meta.k8s.io/v1 Table` with the convertor kube-apiserver uses for the
    # resource (v1.36.2):
    #
    #   :printer    pkg/printers/internalversion AddHandlers through
    #               printerstorage.TableConvertor (every column, Wide)
    #   :default    rest.NewDefaultTableConvertor: Name, Created At (Role,
    #               ClusterRole, LimitRange, CSIStorageCapacity, CRDs, and any
    #               kind without a handler)
    #   :crd        apiextensions tableconvertor over additionalPrinterColumns
    #   :apiservice kube-aggregator's APIService REST
    #
    # Column definitions are upstream's, generated into columns.rb; the cells
    # follow each print function.  The objects printed are the served
    # (versioned) shape, so each printer reads the fields its internal-type
    # counterpart reads after conversion.
    module TablePrinter
      API_VERSION = "meta.k8s.io/v1"
      KIND = "Table"

      # Stores that register rest.NewDefaultTableConvertor although
      # (CSIStorageCapacity) a print handler exists.
      DEFAULT_CONVERTOR_KINDS = %w[CSIStorageCapacity LimitRange Role ClusterRole CustomResourceDefinition].freeze

      DEFAULT_COLUMNS = [
        {"name" => "Name", "type" => "string", "format" => "name", "description" => NAME_DESCRIPTION, "priority" => 0}.freeze,
        {"name" => "Created At", "type" => "date", "format" => "", "description" => CREATION_TIMESTAMP_DESCRIPTION,
         "priority" => 0}.freeze
      ].freeze

      APISERVICE_COLUMNS = [
        {"name" => "Name", "type" => "string", "format" => "name", "description" => NAME_DESCRIPTION, "priority" => 0}.freeze,
        {"name" => "Service", "type" => "string", "format" => "",
         "description" => "The reference to the service that hosts this API endpoint.", "priority" => 0}.freeze,
        {"name" => "Available", "type" => "string", "format" => "", "description" => "Whether this service is available.",
         "priority" => 0}.freeze,
        {"name" => "Age", "type" => "string", "format" => "", "description" => CREATION_TIMESTAMP_DESCRIPTION, "priority" => 0}.freeze
      ].freeze

      # apiextensions serveDefaultColumnsIfEmpty.
      CRD_DEFAULT_COLUMNS = [
        {"name" => "Age", "type" => "date", "description" => CREATION_TIMESTAMP_DESCRIPTION,
         "jsonPath" => ".metadata.creationTimestamp"}.freeze
      ].freeze

      # A print function failed (upstream returns the error, and the request
      # fails with it).
      class PrintError < StandardError; end

      POD_SUCCESS_CONDITIONS = [{"type" => "Completed", "status" => "True", "reason" => "Succeeded",
                                 "message" => "The pod has completed successfully."}.freeze].freeze
      POD_FAILED_CONDITIONS = [{"type" => "Completed", "status" => "True", "reason" => "Failed",
                                "message" => "The pod failed."}.freeze].freeze
      LOAD_BALANCER_WIDTH = 16
      LABEL_NODE_ROLE_PREFIX = "node-role.kubernetes.io/"
      NODE_LABEL_ROLE = "kubernetes.io/role"
      BETA_STORAGE_CLASS_ANNOTATION = "volume.beta.kubernetes.io/storage-class"
      NANOSECOND = 1_000_000_000
      ZERO_TIME = Time.utc(1, 1, 1).freeze

      module_function

      # `include_object`: "Object", "Metadata" (default) or "None", the
      # includeObject parameter of TableOptions; `no_headers` its noHeaders.
      # `convertor`: :printer (default), :default, :apiservice, or [:crd,
      # additionalPrinterColumns].
      def table_for(body, include_object: "Metadata", now: Time.now.utc, no_headers: false, convertor: nil, api_version: API_VERSION)
        return nil unless body.is_a?(Hash)

        list = body["kind"].to_s.end_with?("List") && body["items"].is_a?(Array)
        item_kind = list ? body["kind"].to_s.delete_suffix("List") : body["kind"].to_s
        items = if list
                  body["items"].map do |item|
                    item.merge("kind" => item["kind"] || item_kind, "apiVersion" => item["apiVersion"] || body["apiVersion"])
                  end
                else
                  [body]
                end
        now_r = now.to_r
        columns, rows = convert(convertor || convertor_for(item_kind), item_kind, items, now_r, list: list)
        table = {"kind" => KIND, "apiVersion" => api_version, "metadata" => table_metadata(body, list)}
        # kube-aggregator's APIService convertor ignores noHeaders.
        table["columnDefinitions"] = no_headers && Array(convertor || convertor_for(item_kind)).first != :apiservice ? nil : columns
        table["rows"] = rows.each_with_index.map do |row, index|
          row = {"cells" => row} if row.is_a?(Array)
          attach_object(row, row.delete(:object) || items[index], include_object, api_version)
        end
        table
      end

      def convertor_for(kind)
        return :default if DEFAULT_CONVERTOR_KINDS.include?(kind)
        return :apiservice if kind == "APIService"

        COLUMNS.key?(kind) && CELLS.key?(kind) ? :printer : :default
      end

      def convert(convertor, kind, items, now, list:)
        mode, crd_columns = Array(convertor)
        case mode
        when :printer
          printer = CELLS.fetch(kind)
          items = sort_flow_schemas(items) if list && kind == "FlowSchema"
          rows = items.map do |item|
            row = printer.call(item, now)
            row.is_a?(Hash) ? row.merge(object: item) : {"cells" => row, object: item}
          end
          [COLUMNS.fetch(kind), rows]
        when :apiservice
          [APISERVICE_COLUMNS, items.map { |item| apiservice_cells(item, now) }]
        when :crd
          crd_table(crd_columns, items, now)
        else
          [DEFAULT_COLUMNS, items.map do |item|
            [object_name(item), rfc3339(parse_time(item.dig("metadata", "creationTimestamp")) || ZERO_TIME)]
          end]
        end
      end

      def table_metadata(body, list)
        metadata = body["metadata"].is_a?(Hash) ? body["metadata"] : {}
        result = {"resourceVersion" => metadata["resourceVersion"]}
        if list
          result["continue"] = metadata["continue"]
          result["remainingItemCount"] = metadata["remainingItemCount"]
        end
        result.compact
      end

      def attach_object(row, object, include_object, api_version = API_VERSION)
        row = row.dup
        case include_object.to_s
        when "None" then row.delete("object")
        when "Object" then row["object"] = object
        else row["object"] = partial_object_metadata(object, api_version)
        end
        row
      end

      def partial_object_metadata(object, api_version = API_VERSION)
        {"kind" => "PartialObjectMetadata", "apiVersion" => api_version, "metadata" => object["metadata"] || {}}
      end

      # --------------------------------------------------------------- time

      def parse_time(value)
        return nil if value.nil? || value.to_s.empty?

        time = Time.iso8601(value.to_s)
        time == ZERO_TIME ? nil : time
      rescue ArgumentError
        nil
      end

      def rfc3339(time) = time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      # Go integer division truncates toward zero.
      def go_div(dividend, divisor)
        quotient = dividend.abs / divisor.abs
        dividend.negative? ^ divisor.negative? ? -quotient : quotient
      end

      # k8s.io/apimachinery/pkg/util/duration.HumanDuration, on nanoseconds.
      def human_duration(nanoseconds)
        nanoseconds = nanoseconds.to_i
        seconds = go_div(nanoseconds, NANOSECOND)
        return "<invalid>" if seconds < -1
        return "0s" if seconds.negative?
        return "#{seconds}s" if seconds < 60 * 2

        minutes = go_div(nanoseconds, 60 * NANOSECOND)
        if minutes < 10
          remainder = seconds % 60
          return remainder.zero? ? "#{minutes}m" : "#{minutes}m#{remainder}s"
        end
        return "#{minutes}m" if minutes < 60 * 3

        hours = go_div(nanoseconds, 3600 * NANOSECOND)
        if hours < 8
          remainder = minutes % 60
          return remainder.zero? ? "#{hours}h" : "#{hours}h#{remainder}m"
        end
        return "#{hours}h" if hours < 48

        if hours < 24 * 8
          remainder = hours % 24
          return remainder.zero? ? "#{hours / 24}d" : "#{hours / 24}d#{remainder}h"
        end
        return "#{hours / 24}d" if hours < 24 * 365 * 2

        if hours < 24 * 365 * 8
          remainder = (hours / 24) % 365
          return remainder.zero? ? "#{hours / 24 / 365}y" : "#{hours / 24 / 365}y#{remainder}d"
        end
        "#{hours / 24 / 365}y"
      end

      def elapsed(now, time) = ((now - time.to_r) * NANOSECOND).to_i

      # translateTimestampSince / translateMicroTimestampSince.
      def since(value, now)
        time = value.is_a?(Time) ? value : parse_time(value)
        time ? human_duration(elapsed(now, time)) : "<unknown>"
      end

      def age(object, now) = since(object.dig("metadata", "creationTimestamp"), now)

      # ------------------------------------------------------------ helpers

      def object_name(object) = object.dig("metadata", "name").to_s
      def spec(object) = object["spec"].is_a?(Hash) ? object["spec"] : {}
      def status(object) = object["status"].is_a?(Hash) ? object["status"] : {}
      def annotations(object) = object.dig("metadata", "annotations").is_a?(Hash) ? object.dig("metadata", "annotations") : {}
      def deleting?(object) = !object.dig("metadata", "deletionTimestamp").nil?

      def quantity(value)
        return "0" if value.nil?

        Schema::Quantity.from_json(value).to_s
      rescue Schema::Quantity::ParseError
        value.to_s
      end

      # (*resource.Quantity).String of a pointer field.
      def quantity_ptr(value) = value.nil? ? "<nil>" : quantity(value)

      # intstr.IntOrString.String.
      def int_or_string(value) = value.is_a?(Numeric) ? value.to_i.to_s : value.to_s

      def print_bool(value) = value ? "True" : "False"
      def print_bool_ptr(value) = value.nil? ? "<unset>" : print_bool(value)

      # labels.FormatLabels: Set.String sorts the "key=value" strings.
      def format_labels(map)
        text = (map.is_a?(Hash) ? map : {}).map { |key, value| "#{key}=#{value}" }.sort.join(",")
        text.empty? ? "<none>" : text
      end

      LABEL_NAME = /\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/
      DNS_SUBDOMAIN = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/

      def valid_label_key?(key)
        prefix, name = key.include?("/") ? key.split("/", 2) : [nil, key]
        return false if name.include?("/")
        return false if prefix && (prefix.empty? || prefix.length > 253 || !prefix.match?(DNS_SUBDOMAIN))

        !name.empty? && name.length <= 63 && name.match?(LABEL_NAME)
      end

      def valid_label_value?(value) = value.empty? || (value.length <= 63 && value.match?(LABEL_NAME))

      # metav1.LabelSelectorAsSelector(...).String(); nil when the selector
      # does not convert.  A nil selector is labels.Nothing() and an empty one
      # labels.Everything(), both "".
      def label_selector_string(selector)
        return "" unless selector.is_a?(Hash)

        match_labels = selector["matchLabels"].is_a?(Hash) ? selector["matchLabels"] : {}
        expressions = Array(selector["matchExpressions"])
        return "" if match_labels.empty? && expressions.empty?

        requirements = match_labels.map do |key, value|
          key = key.to_s
          value = value.to_s
          return nil unless valid_label_key?(key) && valid_label_value?(value)

          [key, "#{key}=#{value}"]
        end
        expressions.each do |expression|
          key = expression["key"].to_s
          values = Array(expression["values"]).map(&:to_s)
          operator = expression["operator"].to_s
          return nil unless valid_label_key?(key) && values.all? { |value| valid_label_value?(value) }

          text = case operator
                 when "In", "NotIn"
                   return nil if values.empty?

                   "#{key} #{operator == "In" ? "in" : "notin"} (#{values.length == 1 ? values.first : values.sort.join(",")})"
                 when "Exists", "DoesNotExist"
                   return nil unless values.empty?

                   operator == "Exists" ? key : "!#{key}"
                 else
                   return nil
                 end
          requirements << [key, text]
        end
        # sort.Sort(ByKey): an insertion sort at these sizes, so stable.
        requirements.each_with_index.sort_by { |(key, _), index| [key, index] }.map { |(_, text), _| text }.join(",")
      end

      # metav1.FormatLabelSelector.
      def format_label_selector(selector)
        text = label_selector_string(selector)
        return "<error>" if text.nil?

        text.empty? ? "<none>" : text
      end

      # The generated (*metav1.LabelSelector).String().
      def label_selector_go_string(selector)
        labels = selector["matchLabels"].is_a?(Hash) ? selector["matchLabels"] : {}
        expressions = Array(selector["matchExpressions"]).map do |expression|
          "LabelSelectorRequirement{Key:#{expression["key"]},Operator:#{expression["operator"]}," \
            "Values:[#{Array(expression["values"]).join(" ")}],}"
        end
        map = labels.keys.map(&:to_s).sort.map { |key| "#{key}: #{labels[key]}," }.join
        "&LabelSelector{MatchLabels:map[string]string{#{map}},MatchExpressions:[]LabelSelectorRequirement{" \
          "#{expressions.map { |text| "#{text}," }.join}},}"
      end

      # layoutContainerCells.
      def container_cells(containers)
        containers = Array(containers)
        [containers.map { |container| container["name"].to_s }.join(","),
         containers.map { |container| container["image"].to_s }.join(",")]
      end

      def list_with_more(list, more, count, max)
        text = list.join(",")
        return "#{text} + #{count - max} more..." if more

        text.empty? ? "<unset>" : text
      end

      # sets.String List(): sorted and unique.
      def load_balancer_status(status, wide)
        ingress = Array(status.is_a?(Hash) ? status["ingress"] : nil)
        values = ingress.filter_map do |entry|
          if !entry["ip"].to_s.empty? then entry["ip"].to_s
          elsif !entry["hostname"].to_s.empty? then entry["hostname"].to_s
          end
        end
        text = values.uniq.sort.join(",")
        text = "#{text[0, LOAD_BALANCER_WIDTH - 3]}..." if !wide && text.bytesize > LOAD_BALANCER_WIDTH
        text
      end

      # helper.GetAccessModesAsString.
      def access_modes(modes)
        modes = Array(modes).map(&:to_s)
        {"ReadWriteOnce" => "RWO", "ReadOnlyMany" => "ROX", "ReadWriteMany" => "RWX", "ReadWriteOncePod" => "RWOP"}
          .filter_map { |mode, short| short if modes.include?(mode) }.join(",")
      end

      # schema.GroupResource / GroupKind String().
      def group_qualified(name, group) = group.to_s.empty? ? name.to_s : "#{name}.#{group}"

      def restartable_init_container?(container) = container.is_a?(Hash) && container["restartPolicy"] == "Always"

      def condition_true?(conditions, type)
        condition = Array(conditions).find { |entry| entry["type"] == type }
        condition ? condition["status"] == "True" : false
      end

      # The first podIPs entry; v1 -> internal conversion derives podIPs
      # from a lone podIP.
      def first_pod_ip(status)
        ips = Array(status["podIPs"])
        ips.empty? ? status["podIP"].to_s : ips.first["ip"].to_s
      end

      def cluster_ips(spec)
        ips = Array(spec["clusterIPs"])
        ips.empty? && !spec["clusterIP"].to_s.empty? ? [spec["clusterIP"].to_s] : ips
      end

      # ------------------------------------------------------------- printers

      # printPod.
      def pod_row(pod, now)
        spec = spec(pod)
        status = status(pod)
        restarts = 0
        restartable_restarts = 0
        total = Array(spec["containers"]).length
        ready = 0
        last_restart = nil
        last_restartable_restart = nil
        phase = status["phase"].to_s
        reason = status["reason"].to_s.empty? ? phase : status["reason"].to_s
        conditions = Array(status["conditions"])
        conditions.each do |condition|
          reason = "SchedulingGated" if condition["type"] == "PodScheduled" && condition["reason"] == "SchedulingGated"
        end
        init_containers = {}
        init_specs = Array(spec["initContainers"])
        init_specs.each do |container|
          init_containers[container["name"]] = container
          total += 1 if restartable_init_container?(container)
        end
        later = ->(current, candidate) { candidate && (current.nil? || candidate > current) ? candidate : current }
        initializing = false
        Array(status["initContainerStatuses"]).each_with_index do |container, index|
          restarts += container["restartCount"].to_i
          finished = parse_time(container.dig("lastState", "terminated", "finishedAt")) if container.dig("lastState", "terminated")
          last_restart = later.call(last_restart, finished) if container.dig("lastState", "terminated")
          restartable = restartable_init_container?(init_containers[container["name"]])
          if restartable
            restartable_restarts += container["restartCount"].to_i
            last_restartable_restart = later.call(last_restartable_restart, finished) if container.dig("lastState", "terminated")
          end
          terminated = container.dig("state", "terminated")
          waiting = container.dig("state", "waiting")
          if terminated && terminated["exitCode"].to_i.zero?
            next
          elsif restartable && container["started"] == true
            ready += 1 if container["ready"] == true
            next
          elsif terminated
            reason = if terminated["reason"].to_s.empty?
                       terminated["signal"].to_i.zero? ? "Init:ExitCode:#{terminated["exitCode"].to_i}" : "Init:Signal:#{terminated["signal"].to_i}"
                     else
                       "Init:#{terminated["reason"]}"
                     end
          elsif waiting && !waiting["reason"].to_s.empty? && waiting["reason"] != "PodInitializing"
            reason = "Init:#{waiting["reason"]}"
          else
            reason = "Init:#{index}/#{init_specs.length}"
          end

          initializing = true
          break
        end

        if !initializing || condition_true?(conditions, "Initialized")
          restarts = restartable_restarts
          last_restart = last_restartable_restart
          has_running = false
          error_reason = ""
          Array(status["containerStatuses"]).reverse_each do |container|
            restarts += container["restartCount"].to_i
            if container.dig("lastState", "terminated")
              last_restart = later.call(last_restart, parse_time(container.dig("lastState", "terminated", "finishedAt")))
            end
            waiting = container.dig("state", "waiting")
            terminated = container.dig("state", "terminated")
            if waiting && !waiting["reason"].to_s.empty?
              reason = waiting["reason"].to_s
            elsif terminated
              reason = if !terminated["reason"].to_s.empty? then terminated["reason"].to_s
                       elsif !terminated["signal"].to_i.zero? then "Signal:#{terminated["signal"].to_i}"
                       else "ExitCode:#{terminated["exitCode"].to_i}"
                       end
              error_reason = reason unless terminated["exitCode"].to_i.zero?
            elsif container["ready"] == true && container.dig("state", "running")
              has_running = true
              ready += 1
            end
          end
          if reason == "Completed"
            if has_running && condition_true?(conditions.select do |condition|
              condition["type"] == "Ready" && condition["status"] == "True"
            end, "Ready")
              reason = "Running"
            elsif !error_reason.empty?
              reason = error_reason
            elsif has_running
              reason = "NotReady"
            end
          end
        end

        if deleting?(pod) && status["reason"] == "NodeLost"
          reason = "Unknown"
        elsif deleting?(pod) && !%w[Failed Succeeded].include?(phase)
          reason = "Terminating"
        end
        restarts_text = restarts.to_s
        restarts_text = "#{restarts} (#{since(last_restart, now)} ago)" if !restarts.zero? && last_restart

        pod_ip = first_pod_ip(status)
        gates = Array(spec["readinessGates"])
        readiness = if gates.empty?
                      "<none>"
                    else
                      true_count = gates.count do |gate|
                        match = conditions.find { |condition| condition["type"] == gate["conditionType"] }
                        match && match["status"] == "True"
                      end
                      "#{true_count}/#{gates.length}"
                    end
        cells = [object_name(pod), "#{ready}/#{total}", reason, restarts_text, age(pod, now),
                 pod_ip.empty? ? "<none>" : pod_ip,
                 spec["nodeName"].to_s.empty? ? "<none>" : spec["nodeName"].to_s,
                 status["nominatedNodeName"].to_s.empty? ? "<none>" : status["nominatedNodeName"].to_s,
                 readiness]
        row = {"cells" => cells}
        case phase
        when "Succeeded" then row["conditions"] = POD_SUCCESS_CONDITIONS
        when "Failed" then row["conditions"] = POD_FAILED_CONDITIONS
        end
        row
      end

      def endpoints_text(endpoints)
        subsets = Array(endpoints["subsets"])
        return "<none>" if subsets.empty?

        list = []
        max = 3
        more = false
        count = 0
        subsets.each do |subset|
          addresses = Array(subset["addresses"])
          ports = Array(subset["ports"])
          if ports.empty?
            count += addresses.length
            addresses.each do |address|
              if list.length == max
                more = true
                break
              end
              list << address["ip"].to_s
            end
            next
          end
          ports.each do |port|
            count += addresses.length
            addresses.each do |address|
              if list.length == max
                more = true
                break
              end
              ip = address["ip"].to_s
              list << (ip.include?(":") ? "[#{ip}]:#{port["port"].to_i}" : "#{ip}:#{port["port"].to_i}")
            end
          end
        end
        text = list.join(",")
        more ? "#{text} + #{count - max} more..." : text
      end

      def discovery_ports(ports)
        list = []
        more = false
        count = 0
        Array(ports).each do |port|
          if list.length < 3
            list << (if port["port"].nil?
                       (port["name"].nil? ? "*" : port["name"].to_s)
                     else
                       port["port"].to_i.to_s
                     end)
          elsif list.length == 3
            more = true
          end
          count += 1
        end
        list_with_more(list, more, count, 3)
      end

      def discovery_endpoints(endpoints)
        list = []
        more = false
        count = 0
        Array(endpoints).each do |endpoint|
          Array(endpoint["addresses"]).each do |address|
            if list.length < 3
              list << address.to_s
            elsif list.length == 3
              more = true
            end
            count += 1
          end
        end
        list_with_more(list, more, count, 3)
      end

      def service_external_ip(service)
        spec = spec(service)
        external = Array(spec["externalIPs"]).map(&:to_s)
        case spec["type"].to_s
        when "ClusterIP", "NodePort"
          external.empty? ? "<none>" : external.join(",")
        when "LoadBalancer"
          lb = load_balancer_status(status(service)["loadBalancer"], true)
          unless external.empty?
            results = lb.empty? ? [] : lb.split(",")
            return (results + external).join(",")
          end
          lb.empty? ? "<pending>" : lb
        when "ExternalName"
          spec["externalName"].to_s
        else
          "<unknown>"
        end
      end

      def service_ports(ports)
        Array(ports).map do |port|
          node_port = port["nodePort"].to_i
          node_port.positive? ? "#{port["port"].to_i}:#{node_port}/#{port["protocol"]}" : "#{port["port"].to_i}/#{port["protocol"]}"
        end.join(",")
      end

      def ingress_hosts(rules)
        rules = Array(rules)
        list = []
        more = false
        rules.each do |rule|
          more = true if list.length == 3
          list << rule["host"].to_s if !more && !rule["host"].to_s.empty?
        end
        return "*" if list.empty?

        more ? "#{list.join(",")} + #{rules.length - 3} more..." : list.join(",")
      end

      def param_ref_name(ref)
        return "<unset>" unless ref.is_a?(Hash)

        if !ref["name"].to_s.empty?
          ref["namespace"].to_s.empty? ? "*/#{ref["name"]}" : "#{ref["namespace"]}/#{ref["name"]}"
        elsif ref["selector"].is_a?(Hash)
          label_selector_go_string(ref["selector"])
        else
          "<unset>"
        end
      end

      def param_kind(kind) = kind.is_a?(Hash) ? "#{kind["apiVersion"]}/#{kind["kind"]}" : "<unset>"

      # formatEventSource.
      def event_source(event)
        component = [event.dig("source", "component"), event["reportingComponent"]].map(&:to_s).find { |text| !text.empty? }.to_s
        instance = [event.dig("source", "host"), event["reportingInstance"]].map(&:to_s).find { |text| !text.empty? }.to_s
        instance.empty? ? component : "#{component}, #{instance}"
      end

      # printEvent over the core shape (events.k8s.io/v1 converts into it).
      def event_row(event, now)
        event = EventConversion.to_storage(event) if event["apiVersion"] == EventConversion::API_VERSION
        first_time = parse_time(event["firstTimestamp"])
        first = first_time ? since(first_time, now) : since(event["eventTime"], now)
        last = parse_time(event["lastTimestamp"]) ? since(event["lastTimestamp"], now) : first
        count = event["count"].to_i
        if event["series"].is_a?(Hash)
          last = since(event.dig("series", "lastObservedTime"), now)
          count = event.dig("series", "count").to_i
        elsif count.zero?
          count = 1
        end
        involved = event["involvedObject"].is_a?(Hash) ? event["involvedObject"] : {}
        target = involved["name"].to_s.empty? ? involved["kind"].to_s.downcase : "#{involved["kind"].to_s.downcase}/#{involved["name"]}"
        [last, event["type"].to_s, event["reason"].to_s, target, involved["fieldPath"].to_s, event_source(event),
         event["message"].to_s.strip, first, count, object_name(event)]
      end

      def subjects(subjects)
        users = []
        groups = []
        accounts = []
        Array(subjects).each do |subject|
          case subject["kind"]
          when "ServiceAccount" then accounts << "#{subject["namespace"]}/#{subject["name"]}"
          when "User" then users << subject["name"].to_s
          when "Group" then groups << subject["name"].to_s
          end
        end
        [users.join(", "), groups.join(", "), accounts.join(", ")]
      end

      def csr_status(csr)
        types = Array(status(csr)["conditions"]).map { |condition| condition["type"] }
        text = if types.include?("Denied") then "Denied"
               elsif types.include?("Approved") then "Approved"
               else "Pending"
               end
        text += ",Failed" if types.include?("Failed")
        text += ",Issued" unless status(csr)["certificate"].to_s.empty?
        text
      end

      def hpa_metrics(specs, statuses)
        specs = Array(specs)
        statuses = Array(statuses)
        return "<none>" if specs.empty?

        list = specs.each_with_index.map do |metric, index|
          current_status = statuses[index]
          case metric["type"]
          when "External" then hpa_value_metric(metric["external"], current_status && current_status["external"])
          when "Pods"
            current = if current_status && current_status["pods"]
                        quantity_ptr(current_status.dig("pods", "current",
                                                        "averageValue"))
                      else
                        "<unknown>"
                      end
            "#{current}/#{quantity_ptr(metric.dig("pods", "target", "averageValue"))}"
          when "Object" then hpa_value_metric(metric["object"], current_status && current_status["object"])
          when "Resource" then hpa_resource_metric(metric["resource"], current_status && current_status["resource"])
          when "ContainerResource" then hpa_resource_metric(metric["containerResource"],
                                                            current_status && current_status["containerResource"])
          else "<unknown type>"
          end
        end
        count = list.length
        return list.join(", ") if count <= 2

        "#{list.first(2).join(", ")} + #{count - 2} more..."
      end

      def hpa_value_metric(source, current_status)
        target = source.is_a?(Hash) ? source["target"] || {} : {}
        if target["averageValue"].nil?
          current = current_status ? quantity_ptr(current_status.dig("current", "value")) : "<unknown>"
          "#{current}/#{quantity_ptr(target["value"])}"
        else
          current = "<unknown>"
          current = quantity(current_status.dig("current", "averageValue")) if current_status && !current_status.dig("current",
                                                                                                                     "averageValue").nil?
          "#{current}/#{quantity(target["averageValue"])} (avg)"
        end
      end

      def hpa_resource_metric(source, current_status)
        source = {} unless source.is_a?(Hash)
        target = source["target"] || {}
        if target["averageValue"].nil?
          utilization = current_status && current_status.dig("current", "averageUtilization")
          current = utilization.nil? ? "<unknown>" : "#{utilization.to_i}%"
          wanted = target["averageUtilization"].nil? ? "<auto>" : "#{target["averageUtilization"].to_i}%"
          "#{source["name"]}: #{current}/#{wanted}"
        else
          current = current_status ? quantity_ptr(current_status.dig("current", "averageValue")) : "<unknown>"
          "#{source["name"]}: #{current}/#{quantity(target["averageValue"])}"
        end
      end

      # The internal autoscaling type is the v2 shape; autoscaling/v1 objects
      # convert into it first.
      def hpa_row(hpa, now)
        hpa = HPAConversion.to_v2(hpa) if hpa["apiVersion"] == "autoscaling/v1"
        spec = spec(hpa)
        target = spec["scaleTargetRef"].is_a?(Hash) ? spec["scaleTargetRef"] : {}
        [object_name(hpa), "#{target["kind"]}/#{target["name"]}", hpa_metrics(spec["metrics"], status(hpa)["currentMetrics"]),
         spec["minReplicas"].nil? ? "<unset>" : spec["minReplicas"].to_i.to_s, spec["maxReplicas"].to_i,
         status(hpa)["currentReplicas"].to_i, age(hpa, now)]
      end

      def resource_quota_row(quota, now)
        hard = status(quota)["hard"].is_a?(Hash) ? status(quota)["hard"] : {}
        used = status(quota)["used"].is_a?(Hash) ? status(quota)["used"] : {}
        requests = []
        limits = []
        hard.keys.map(&:to_s).sort.each do |resource|
          pieces = resource.split(".")
          target = pieces.length > 1 && pieces.first == "limits" ? limits : requests
          target << "#{resource}: #{quantity(used[resource])}/#{quantity(hard[resource])}"
        end
        [object_name(quota), requests.join(", "), limits.join(", "), age(quota, now)]
      end

      def controller_revision_row(revision, now)
        owner = Array(revision.dig("metadata", "ownerReferences")).find { |reference| reference["controller"] == true }
        controller = "<none>"
        if owner
          api_version = owner["apiVersion"].to_s
          raise PrintError, "unexpected GroupVersion string: #{api_version}" if api_version.count("/") > 1

          group = api_version.include?("/") ? api_version.split("/", 2).first : ""
          kind = owner["kind"].to_s
          controller = kind.empty? && group.empty? ? owner["name"].to_s : "#{group_qualified(kind, group).downcase}/#{owner["name"]}"
        end
        [object_name(revision), controller, revision["revision"].to_i, age(revision, now)]
      end

      def resource_claim_state(claim)
        states = []
        states << "deleted" if deleting?(claim)
        if status(claim)["allocation"].nil?
          states << "pending" unless deleting?(claim)
        else
          states << "allocated"
          states << "reserved" unless Array(status(claim)["reservedFor"]).empty?
        end
        states.join(",")
      end

      def pool_status_request_row(request, now)
        status = request["status"]
        text = "Pending"
        pool_count = 0
        counts = %w[- - - - -]
        completed = nil
        if status.is_a?(Hash)
          failed = false
          Array(status["conditions"]).each do |condition|
            if condition["type"] == "Complete" && condition["status"] == "True"
              text = "Complete"
              completed = parse_time(condition["lastTransitionTime"]) || :zero
              break
            end
            next unless condition["type"] == "Failed" && condition["status"] == "True"

            text = "Failed"
            failed = true
            break
          end
          pool_count = status["poolCount"].to_i
          pools = Array(status["pools"])
          text = "Complete (#{pools.length}/#{pool_count} pools)" if text == "Complete" && pool_count > pools.length
          unless failed
            sums = %w[totalDevices availableDevices allocatedDevices unavailableDevices].map do |field|
              pools.sum { |pool| pool[field].to_i }
            end
            counts = sums.map(&:to_s) + [pools.count { |pool| !pool["validationError"].nil? }.to_s]
          end
        end
        completed_text = if completed.nil?
                           "<none>"
                         else
                           (completed == :zero ? "<unknown>" : since(completed, now))
                         end
        [object_name(request), spec(request)["driver"].to_s, *counts, pool_count, text, completed_text]
      end

      def storage_version_migration_row(migration, _now)
        resource = spec(migration)["resource"].is_a?(Hash) ? spec(migration)["resource"] : {}
        state = "Unknown"
        Array(status(migration)["conditions"]).each do |condition|
          next unless condition["status"] == "True"

          state = condition["type"] if %w[Running Failed Succeeded].include?(condition["type"])
        end
        [object_name(migration), group_qualified(resource["resource"], resource["group"]), state]
      end

      def pod_group_row(group, now)
        policy = spec(group).dig("schedulingPolicy", "gang").nil? ? "Basic" : "Gang"
        conditions = Array(status(group)["conditions"]).to_h { |condition| [condition["type"], condition] }
        state = "Pending"
        state = conditions["PodGroupScheduled"]["status"] == "True" ? "Scheduled" : "Unschedulable" if conditions["PodGroupScheduled"]
        state = conditions["DisruptionTarget"]["reason"].to_s if conditions["DisruptionTarget"]
        ref = spec(group)["podGroupTemplateRef"]
        workload = ref.is_a?(Hash) ? ref.dig("workload", "workloadName").to_s : "<none>"
        [object_name(group), policy, workload, state, age(group, now)]
      end

      def priority_level_row(level, now)
        limited = spec(level)["limited"]
        values = ["<none>"] * 4
        if limited.is_a?(Hash)
          values[0] = limited["nominalConcurrencyShares"].to_i
          queuing = limited.dig("limitResponse", "queuing")
          values[1, 3] = [queuing["queues"].to_i, queuing["handSize"].to_i, queuing["queueLengthLimit"].to_i] if queuing.is_a?(Hash)
        end
        [object_name(level), spec(level)["type"].to_s, *values, age(level, now)]
      end

      def sort_flow_schemas(items)
        items.each_with_index.sort_by do |item, index|
          [spec(item)["matchingPrecedence"].to_i, object_name(item), index]
        end.map(&:first)
      end

      def apiservice_cells(service, now)
        reference = spec(service)["service"]
        target = reference.is_a?(Hash) ? "#{reference["namespace"]}/#{reference["name"]}" : "Local"
        condition = Array(status(service)["conditions"]).find { |entry| entry["type"] == "Available" }
        available = "Unknown"
        if condition
          available = if condition["status"] == "True" || condition["reason"].to_s.empty?
                        condition["status"].to_s
                      else
                        "#{condition["status"]} (#{condition["reason"]})"
                      end
        end
        [object_name(service), target, available, since(service.dig("metadata", "creationTimestamp"), now)]
      end

      # apiextensions tableconvertor.New and ConvertToTable.
      # A served version's printer columns, with serveDefaultColumnsIfEmpty.
      def crd_columns(columns)
        columns = Array(columns)
        columns.empty? ? CRD_DEFAULT_COLUMNS : columns
      end

      def crd_table(columns, items, now)
        headers = [DEFAULT_COLUMNS.first]
        columns = Array(columns)
        paths = columns.map do |column|
          path = column["jsonPath"].to_s
          description = column["description"].to_s.empty? ? "Custom resource definition column (in JSONPath format): #{path}" : column["description"].to_s
          headers << {"name" => column["name"].to_s, "type" => column["type"].to_s, "format" => column["format"].to_s,
                      "description" => description, "priority" => column["priority"].to_i}
          JSONPath.parse("{#{path}}", allow_missing_keys: true)
        rescue JSONPath::Error
          raise PrintError, "unrecognized column definition #{path.inspect}"
        end
        rows = items.map do |item|
          cells = [object_name(item)]
          paths.each_with_index do |path, index|
            results = begin
              path.find_results(item)
            rescue JSONPath::Error
              nil
            end
            if results.nil? || results.empty? || results.first.empty?
              cells << nil
              next
            end
            value = results.first.first
            type = headers[index + 1]["type"]
            cells << if type == "string"
                       begin
                         path.print_results([value])
                       rescue JSONPath::Error
                         nil
                       end
                     else
                       crd_cell(type, value, now)
                     end
          end
          cells
        end
        [headers, rows]
      end

      # cellForJSONValue.
      def crd_cell(type, value, now)
        return nil if value.nil?

        case type
        when "integer"
          return value if value.is_a?(Integer)
          # int64(float64): out of range (and NaN) is 0x8000000000000000 on amd64.
          return value.finite? && value > -(2**63) - 1 && value < 2**63 ? value.to_i : -(2**63) if value.is_a?(Float)
        when "number"
          return value.to_f if value.is_a?(Numeric)
        when "boolean"
          return value if [true, false].include?(value)
        when "date"
          return nil unless value.is_a?(String)
          # UnmarshalQueryParameter: "" and "null" are the zero time.
          return "<unknown>" if value.empty? || value == "null"

          begin
            time = Time.iso8601(value)
          rescue ArgumentError
            return "<invalid>"
          end
          return time == ZERO_TIME ? "<unknown>" : human_duration(elapsed(now, time))
        end
        nil
      end

      CELLS = {
        "Pod" => method(:pod_row),
        "PodTemplate" => lambda do |template, _now|
          containers, images = container_cells(template.dig("template", "spec", "containers"))
          [object_name(template), containers, images, format_labels(template.dig("template", "metadata", "labels"))]
        end,
        "PodDisruptionBudget" => lambda do |budget, now|
          spec = spec(budget)
          [object_name(budget), spec["minAvailable"].nil? ? "N/A" : int_or_string(spec["minAvailable"]),
           spec["maxUnavailable"].nil? ? "N/A" : int_or_string(spec["maxUnavailable"]),
           status(budget)["disruptionsAllowed"].to_i, age(budget, now)]
        end,
        "ReplicationController" => lambda do |controller, now|
          spec = spec(controller)
          containers, images = container_cells(spec.dig("template", "spec", "containers"))
          [object_name(controller), spec["replicas"].to_i, status(controller)["replicas"].to_i, status(controller)["readyReplicas"].to_i,
           age(controller, now), containers, images, format_labels(spec["selector"])]
        end,
        "ReplicaSet" => lambda do |set, now|
          spec = spec(set)
          containers, images = container_cells(spec.dig("template", "spec", "containers"))
          [object_name(set), spec["replicas"].to_i, status(set)["replicas"].to_i, status(set)["readyReplicas"].to_i, age(set, now),
           containers, images, format_label_selector(spec["selector"])]
        end,
        "DaemonSet" => lambda do |set, now|
          spec = spec(set)
          status = status(set)
          containers, images = container_cells(spec.dig("template", "spec", "containers"))
          [object_name(set), status["desiredNumberScheduled"].to_i, status["currentNumberScheduled"].to_i, status["numberReady"].to_i,
           status["updatedNumberScheduled"].to_i, status["numberAvailable"].to_i, format_labels(spec.dig("template", "spec", "nodeSelector")),
           age(set, now), containers, images, format_label_selector(spec["selector"])]
        end,
        "Job" => lambda do |job, now|
          spec = spec(job)
          status = status(job)
          succeeded = status["succeeded"].to_i
          completions = if !spec["completions"].nil?
                          "#{succeeded}/#{spec["completions"].to_i}"
                        elsif spec["parallelism"].to_i > 1
                          "#{succeeded}/1 of #{spec["parallelism"].to_i}"
                        else
                          "#{succeeded}/1"
                        end
          started = parse_time(status["startTime"])
          finished = parse_time(status["completionTime"])
          duration = if status["startTime"].nil? then ""
                     elsif status["completionTime"].nil? then human_duration(elapsed(now, started || ZERO_TIME))
                     else human_duration(((finished || ZERO_TIME).to_r - (started || ZERO_TIME).to_r) * NANOSECOND)
                     end
          conditions = status["conditions"]
          state = if condition_true?(conditions, "Complete") then "Complete"
                  elsif condition_true?(conditions, "Failed") then "Failed"
                  elsif deleting?(job) then "Terminating"
                  elsif condition_true?(conditions, "Suspended") then "Suspended"
                  elsif condition_true?(conditions, "FailureTarget") then "FailureTarget"
                  elsif condition_true?(conditions, "SuccessCriteriaMet") then "SuccessCriteriaMet"
                  else "Running"
                  end
          containers, images = container_cells(spec.dig("template", "spec", "containers"))
          [object_name(job), state, completions, duration, age(job, now), containers, images, format_label_selector(spec["selector"])]
        end,
        "CronJob" => lambda do |job, now|
          spec = spec(job)
          last = status(job)["lastScheduleTime"]
          template = spec.dig("jobTemplate", "spec") || {}
          containers, images = container_cells(template.dig("template", "spec", "containers"))
          [object_name(job), spec["schedule"].to_s, spec["timeZone"].nil? ? "<none>" : spec["timeZone"].to_s, print_bool_ptr(spec["suspend"]),
           Array(status(job)["active"]).length, last.nil? ? "<none>" : since(last, now), age(job, now),
           containers, images, format_label_selector(template["selector"])]
        end,
        "Service" => lambda do |service, now|
          spec = spec(service)
          ips = cluster_ips(spec)
          ports = service_ports(spec["ports"])
          [object_name(service), spec["type"].to_s, ips.empty? ? "<none>" : ips.first.to_s, service_external_ip(service),
           ports.empty? ? "<none>" : ports, age(service, now), format_labels(spec["selector"])]
        end,
        "Ingress" => lambda do |ingress, now|
          spec = spec(ingress)
          [object_name(ingress), spec["ingressClassName"].nil? ? "<none>" : spec["ingressClassName"].to_s, ingress_hosts(spec["rules"]),
           load_balancer_status(status(ingress)["loadBalancer"], true), Array(spec["tls"]).empty? ? "80" : "80, 443", age(ingress, now)]
        end,
        "IngressClass" => lambda do |ingress_class, now|
          label = object_name(ingress_class)
          label += " (default)" if annotations(ingress_class)["ingressclass.kubernetes.io/is-default-class"] == "true"
          parameters = spec(ingress_class)["parameters"]
          text = "<none>"
          if parameters.is_a?(Hash)
            text = parameters["kind"].to_s
            text += ".#{parameters["apiGroup"]}" unless parameters["apiGroup"].nil?
            text += "/#{parameters["name"]}"
          end
          [label, spec(ingress_class)["controller"].to_s, text, age(ingress_class, now)]
        end,
        "StatefulSet" => lambda do |set, now|
          containers, images = container_cells(spec(set).dig("template", "spec", "containers"))
          [object_name(set), "#{status(set)["readyReplicas"].to_i}/#{spec(set)["replicas"].to_i}", age(set, now), containers, images]
        end,
        "Endpoints" => ->(endpoints, now) { [object_name(endpoints), endpoints_text(endpoints), age(endpoints, now)] },
        "Node" => lambda do |node, now|
          spec = spec(node)
          status = status(node)
          ready = Array(status["conditions"]).select { |condition| condition["type"] == "Ready" }.last
          states = if ready
                     [ready["status"] == "True" ? "Ready" : "NotReady"]
                   else
                     ["Unknown"]
                   end
          states << "SchedulingDisabled" if spec["unschedulable"] == true
          labels = node.dig("metadata", "labels").is_a?(Hash) ? node.dig("metadata", "labels") : {}
          roles = labels.filter_map do |key, value|
            if key.start_with?(LABEL_NODE_ROLE_PREFIX)
              role = key.delete_prefix(LABEL_NODE_ROLE_PREFIX)
              role unless role.empty?
            elsif key == NODE_LABEL_ROLE && !value.to_s.empty?
              value.to_s
            end
          end.uniq.sort
          info = status["nodeInfo"].is_a?(Hash) ? status["nodeInfo"] : {}
          kernel = info["kernelVersion"].to_s.empty? ? "<unknown>" : info["kernelVersion"].to_s
          kernel += " (#{info["architecture"]})" unless info["architecture"].to_s.empty?
          addresses = Array(status["addresses"])
          address = lambda do |type|
            entry = addresses.find { |candidate| candidate["type"] == type }
            entry ? entry["address"].to_s : "<none>"
          end
          [object_name(node), states.join(","), roles.empty? ? "<none>" : roles.join(","), age(node, now), info["kubeletVersion"].to_s,
           address.call("InternalIP"), address.call("ExternalIP"),
           info["osImage"].to_s.empty? ? "<unknown>" : info["osImage"].to_s, kernel,
           info["containerRuntimeVersion"].to_s.empty? ? "<unknown>" : info["containerRuntimeVersion"].to_s]
        end,
        "Event" => method(:event_row),
        "Namespace" => ->(namespace, now) { [object_name(namespace), status(namespace)["phase"].to_s, age(namespace, now)] },
        "Secret" => lambda do |secret, now|
          [object_name(secret), secret["type"].to_s, (secret["data"].is_a?(Hash) ? secret["data"].length : 0), age(secret, now)]
        end,
        "ServiceAccount" => ->(account, now) { [object_name(account), age(account, now)] },
        "PersistentVolume" => lambda do |volume, now|
          spec = spec(volume)
          claim = spec["claimRef"]
          class_name = annotations(volume).key?(BETA_STORAGE_CLASS_ANNOTATION) ? annotations(volume)[BETA_STORAGE_CLASS_ANNOTATION].to_s : spec["storageClassName"].to_s
          [object_name(volume), quantity(spec.dig("capacity", "storage")), access_modes(spec["accessModes"]),
           spec["persistentVolumeReclaimPolicy"].to_s, deleting?(volume) ? "Terminating" : status(volume)["phase"].to_s,
           claim.is_a?(Hash) ? "#{claim["namespace"]}/#{claim["name"]}" : "", class_name,
           spec["volumeAttributesClassName"].nil? ? "<unset>" : spec["volumeAttributesClassName"].to_s,
           status(volume)["reason"].to_s, age(volume, now), spec["volumeMode"].nil? ? "<unset>" : spec["volumeMode"].to_s]
        end,
        "PersistentVolumeClaim" => lambda do |claim, now|
          spec = spec(claim)
          capacity = ""
          modes = ""
          unless spec["volumeName"].to_s.empty?
            modes = access_modes(status(claim)["accessModes"])
            capacity = quantity(status(claim).dig("capacity", "storage"))
          end
          class_name = if annotations(claim).key?(BETA_STORAGE_CLASS_ANNOTATION) then annotations(claim)[BETA_STORAGE_CLASS_ANNOTATION].to_s
                       else spec["storageClassName"].to_s
                       end
          [object_name(claim), deleting?(claim) ? "Terminating" : status(claim)["phase"].to_s, spec["volumeName"].to_s, capacity, modes,
           class_name, spec["volumeAttributesClassName"].nil? ? "<unset>" : spec["volumeAttributesClassName"].to_s, age(claim, now),
           spec["volumeMode"].nil? ? "<unset>" : spec["volumeMode"].to_s]
        end,
        "ComponentStatus" => lambda do |component, _now|
          condition = Array(component["conditions"]).find { |entry| entry["type"] == "Healthy" }
          state = if condition.nil?
                    "Unknown"
                  else
                    (condition["status"] == "True" ? "Healthy" : "Unhealthy")
                  end
          [object_name(component), state, condition.to_h["message"].to_s, condition.to_h["error"].to_s]
        end,
        "Deployment" => lambda do |deployment, now|
          spec = spec(deployment)
          status = status(deployment)
          selector = label_selector_string(spec["selector"])
          containers, images = container_cells(spec.dig("template", "spec", "containers"))
          [object_name(deployment), "#{status["readyReplicas"].to_i}/#{spec["replicas"].to_i}", status["updatedReplicas"].to_i,
           status["availableReplicas"].to_i, age(deployment, now), containers, images, selector.nil? ? "<invalid>" : selector]
        end,
        "HorizontalPodAutoscaler" => method(:hpa_row),
        "ConfigMap" => lambda do |map, now|
          count = (map["data"].is_a?(Hash) ? map["data"].length : 0) + (map["binaryData"].is_a?(Hash) ? map["binaryData"].length : 0)
          [object_name(map), count, age(map, now)]
        end,
        "NetworkPolicy" => lambda { |policy, now|
          [object_name(policy), format_label_selector(spec(policy)["podSelector"] || {}), age(policy, now)]
        },
        "RoleBinding" => lambda do |binding, now|
          ref = binding["roleRef"].is_a?(Hash) ? binding["roleRef"] : {}
          [object_name(binding), "#{ref["kind"]}/#{ref["name"]}", age(binding, now), *subjects(binding["subjects"])]
        end,
        "ClusterRoleBinding" => lambda do |binding, now|
          ref = binding["roleRef"].is_a?(Hash) ? binding["roleRef"] : {}
          [object_name(binding), "#{ref["kind"]}/#{ref["name"]}", age(binding, now), *subjects(binding["subjects"])]
        end,
        "CertificateSigningRequest" => lambda do |csr, now|
          spec = spec(csr)
          [object_name(csr), age(csr, now), spec["signerName"].to_s.empty? ? "<none>" : spec["signerName"].to_s, spec["username"].to_s,
           spec["expirationSeconds"].nil? ? "<none>" : human_duration(spec["expirationSeconds"].to_i * NANOSECOND), csr_status(csr)]
        end,
        "ClusterTrustBundle" => lambda do |bundle, _now|
          [object_name(bundle), spec(bundle)["signerName"].to_s.empty? ? "<none>" : spec(bundle)["signerName"].to_s]
        end,
        "PodCertificateRequest" => lambda do |request, _now|
          spec = spec(request)
          state = "Pending"
          Array(status(request)["conditions"]).each do |condition|
            state = condition["type"] if %w[Issued Denied Failed].include?(condition["type"])
          end
          [object_name(request), spec["podName"].to_s, spec["serviceAccountName"].to_s, spec["nodeName"].to_s, spec["signerName"].to_s, state,
           format_labels(spec["unverifiedUserAnnotations"])]
        end,
        "Lease" => ->(lease, now) { [object_name(lease), spec(lease)["holderIdentity"].to_s, age(lease, now)] },
        "LeaseCandidate" => lambda do |candidate, now|
          spec = spec(candidate)
          [object_name(candidate), spec["leaseName"].to_s, spec["binaryVersion"].to_s, spec["emulationVersion"].to_s, age(candidate, now)]
        end,
        "StorageClass" => lambda do |storage_class, now|
          label = object_name(storage_class)
          label += " (default)" if %w[storageclass.kubernetes.io/is-default-class storageclass.beta.kubernetes.io/is-default-class]
            .any? { |key| annotations(storage_class)[key] == "true" }
          [label, storage_class["provisioner"].to_s, (storage_class["reclaimPolicy"] || "Delete").to_s,
           (storage_class["volumeBindingMode"] || "Immediate").to_s, storage_class["allowVolumeExpansion"] == true, age(storage_class, now)]
        end,
        "VolumeAttributesClass" => ->(vac, now) { [object_name(vac), vac["driverName"].to_s, age(vac, now)] },
        "Status" => ->(status, _now) { [status["status"].to_s, status["reason"].to_s, status["message"].to_s] },
        "ControllerRevision" => method(:controller_revision_row),
        "ResourceQuota" => method(:resource_quota_row),
        "PriorityClass" => lambda do |priority_class, now|
          [object_name(priority_class), priority_class["value"].to_i, priority_class["globalDefault"] == true, age(priority_class, now),
           priority_class["preemptionPolicy"].to_s]
        end,
        "RuntimeClass" => ->(runtime_class, now) { [object_name(runtime_class), runtime_class["handler"].to_s, age(runtime_class, now)] },
        "VolumeAttachment" => lambda do |attachment, now|
          spec = spec(attachment)
          [object_name(attachment), spec["attacher"].to_s, spec.dig("source", "persistentVolumeName").to_s, spec["nodeName"].to_s,
           status(attachment)["attached"] == true, age(attachment, now)]
        end,
        "EndpointSlice" => lambda do |slice, now|
          [object_name(slice), slice["addressType"].to_s, discovery_ports(slice["ports"]), discovery_endpoints(slice["endpoints"]),
           age(slice, now)]
        end,
        "CSINode" => ->(node, now) { [object_name(node), Array(spec(node)["drivers"]).length, age(node, now)] },
        "CSIDriver" => lambda do |driver, now|
          spec = spec(driver)
          modes = Array(spec["volumeLifecycleModes"]).join(",")
          tokens = if spec["tokenRequests"].nil?
                     "<unset>"
                   else
                     Array(spec["tokenRequests"]).map do |request|
                       request["audience"].to_s
                     end.join(",")
                   end
          [object_name(driver), spec["attachRequired"].nil? || spec["attachRequired"] == true, spec["podInfoOnMount"] == true,
           spec["storageCapacity"] == true, tokens, spec["requiresRepublish"] == true, modes.empty? ? "<none>" : modes, age(driver, now)]
        end,
        "CSIStorageCapacity" => lambda do |capacity, _now|
          [object_name(capacity), capacity["storageClassName"].to_s, capacity["capacity"].nil? ? "<unset>" : quantity(capacity["capacity"])]
        end,
        "MutatingWebhookConfiguration" => ->(config, now) { [object_name(config), Array(config["webhooks"]).length, age(config, now)] },
        "ValidatingWebhookConfiguration" => ->(config, now) { [object_name(config), Array(config["webhooks"]).length, age(config, now)] },
        "ValidatingAdmissionPolicy" => lambda do |policy, now|
          [object_name(policy), Array(spec(policy)["validations"]).length, param_kind(spec(policy)["paramKind"]), age(policy, now)]
        end,
        "ValidatingAdmissionPolicyBinding" => lambda do |binding, now|
          [object_name(binding), spec(binding)["policyName"].to_s, param_ref_name(spec(binding)["paramRef"]), age(binding, now)]
        end,
        "MutatingAdmissionPolicy" => lambda do |policy, now|
          [object_name(policy), Array(spec(policy)["mutations"]).length, param_kind(spec(policy)["paramKind"]), age(policy, now)]
        end,
        "MutatingAdmissionPolicyBinding" => lambda do |binding, now|
          [object_name(binding), spec(binding)["policyName"].to_s, param_ref_name(spec(binding)["paramRef"]), age(binding, now)]
        end,
        "FlowSchema" => lambda do |schema, now|
          spec = spec(schema)
          method = spec.dig("distinguisherMethod", "type")
          dangling = Array(status(schema)["conditions"]).find { |condition| condition["type"] == "Dangling" }
          [object_name(schema), spec.dig("priorityLevelConfiguration", "name").to_s, spec["matchingPrecedence"].to_i,
           spec["distinguisherMethod"].nil? ? "<none>" : method.to_s, age(schema, now), dangling ? dangling["status"].to_s : "?"]
        end,
        "PriorityLevelConfiguration" => method(:priority_level_row),
        "StorageVersion" => lambda do |version, now|
          versions = Array(status(version)["storageVersions"])
          list = versions.first(3).map { |entry| "#{entry["apiServerID"]}=#{entry["encodingVersion"]}" }
          encoding = status(version)["commonEncodingVersion"]
          [object_name(version), encoding.nil? ? "<unset>" : encoding.to_s, list_with_more(list, versions.length > 3, versions.length, 3),
           age(version, now)]
        end,
        "Scale" => ->(scale, now) { [object_name(scale), spec(scale)["replicas"].to_i, status(scale)["replicas"].to_i, age(scale, now)] },
        "DeviceClass" => ->(device_class, now) { [object_name(device_class), age(device_class, now)] },
        "ResourceClaim" => ->(claim, now) { [object_name(claim), resource_claim_state(claim), age(claim, now)] },
        "ResourceClaimTemplate" => ->(template, now) { [object_name(template), age(template, now)] },
        "ResourceSlice" => lambda do |slice, now|
          spec = spec(slice)
          [object_name(slice), spec["nodeName"].to_s, spec["driver"].to_s, spec.dig("pool", "name").to_s, age(slice, now)]
        end,
        "ResourcePoolStatusRequest" => method(:pool_status_request_row),
        "DeviceTaintRule" => lambda do |rule, now|
          taint = spec(rule)["taint"].is_a?(Hash) ? spec(rule)["taint"] : {}
          [object_name(rule), taint["key"].to_s, taint["value"].to_s, taint["effect"].to_s,
           taint["timeAdded"].nil? ? "" : since(taint["timeAdded"], now), age(rule, now)]
        end,
        "ServiceCIDR" => ->(cidr, now) { [object_name(cidr), Array(spec(cidr)["cidrs"]).join(","), age(cidr, now)] },
        "IPAddress" => lambda do |address, now|
          ref = spec(address)["parentRef"]
          parent = "<none>"
          if ref.is_a?(Hash)
            parent = group_qualified(ref["resource"], ref["group"]).downcase
            parent += "/#{ref["namespace"]}" unless ref["namespace"].to_s.empty?
            parent += "/#{ref["name"]}"
          end
          [object_name(address), parent, age(address, now)]
        end,
        "StorageVersionMigration" => method(:storage_version_migration_row),
        "Workload" => ->(workload, now) { [object_name(workload), age(workload, now)] },
        "PodGroup" => method(:pod_group_row)
      }.freeze
    end
  end
end

require_relative "event_conversion"
require_relative "hpa_conversion"
