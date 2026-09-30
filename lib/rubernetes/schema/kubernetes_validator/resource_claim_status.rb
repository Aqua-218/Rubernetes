# frozen_string_literal: true

require "json"

module Rubernetes
  module Schema
    # pkg/apis/resource/validation ValidateResourceClaimStatusUpdate
    # (v1.36.2): reservedFor, the per-device status of DRAResourceClaimDevice-
    # Status (Beta on: conditions, data, networkData, only for allocated
    # devices), and the allocation (immutable once set).
    module KubernetesValidator
      module_function

      RESERVED_FOR_MAX = 256
      ALLOCATION_RESULTS_MAX = 32
      DEVICE_STATUS_MAX_CONDITIONS = 8
      DEVICE_STATUS_DATA_MAX = 10 * 1024
      NETWORK_MAX_IPS = 16
      NETWORK_INTERFACE_MAX = 256
      NETWORK_HARDWARE_MAX = 128
      BINDING_CONDITIONS_MAX = 4
      CONDITION_REASON = /\A[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?\z/
      CONDITION_REASON_MSG = "a condition reason must start with alphabetic character, optionally followed by a string of alphanumeric " \
                             "characters or '_,:', and must end with an alphanumeric character or '_' (e.g. 'my_name',  or 'MY_NAME',  " \
                             "or 'MyName',  or 'ReasonA,ReasonB',  or 'ReasonA:ReasonB', regex used for validation is " \
                             "'[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?')"
      UUID = /\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/

      def resource_claim_status_errors(root, old)
        status = fetch(root, "status")
        status = {} unless status.is_a?(Hash)
        old_status = old.is_a?(Hash) ? fetch(old, "status") : nil
        old_status = {} unless old_status.is_a?(Hash)
        request_names = claim_request_names(fetch(root, "spec"))
        issues = []

        reserved = Array(fetch(status, "reservedFor"))
        if reserved.length > RESERVED_FOR_MAX
          issues << issue(%w[status reservedFor], :too_many,
                          "must have at most #{RESERVED_FOR_MAX} items")
        end
        seen = {}
        reserved.each_with_index do |consumer, index|
          consumer = {} unless consumer.is_a?(Hash)
          path = ["status", "reservedFor", index.to_s]
          %w[resource name uid].each { |key| issues << issue(path + [key], :required, "") if blank?(fetch(consumer, key)) }
          uid = fetch(consumer, "uid").to_s
          issues << issue(path, :duplicate, "") if !uid.empty? && seen[uid]
          seen[uid] = true
        end

        allocation = fetch(status, "allocation")
        allocated = claim_allocated_devices(allocation)
        device_seen = {}
        Array(fetch(status, "devices")).each_with_index do |device, index|
          device = {} unless device.is_a?(Hash)
          path = ["status", "devices", index.to_s]
          key = claim_device_id(device)
          issues << issue(path, :duplicate, "") if device_seen[key]
          device_seen[key] = true
          issues.concat(claim_device_status_errors(device, path, allocated))
        end

        unless reserved.empty?
          if allocation.nil?
            issues << issue(%w[status reservedFor], :forbidden, "may not be specified when `allocated` is not set")
          elsif claim_deleted?(root)
            before = Array(fetch(old_status, "reservedFor"))
            if reserved.any? { |entry| !before.include?(entry) }
              issues << issue(%w[status reservedFor], :forbidden,
                              "new entries may not be added while `deallocationRequested` or `deletionTimestamp` are set")
            end
          end
        end

        old_allocation = fetch(old_status, "allocation")
        if old_allocation && allocation
          issues << issue(%w[status allocation], :invalid, "field is immutable") unless old_allocation == allocation
        elsif allocation.is_a?(Hash)
          issues.concat(claim_allocation_errors(allocation, request_names))
        end
        issues
      end

      def claim_deleted?(root)
        metadata = fetch(root, "metadata")
        metadata.is_a?(Hash) && !blank?(fetch(metadata, "deletionTimestamp"))
      end

      # gatherRequestNames: requests and "request/subrequest".
      def claim_request_names(spec)
        names = {}
        Array(spec.is_a?(Hash) ? fetch(fetch(spec, "devices") || {}, "requests") : nil).each do |request|
          next unless request.is_a?(Hash)

          name = fetch(request, "name").to_s
          names[name] = true
          Array(fetch(request, "firstAvailable")).each do |sub|
            names["#{name}/#{fetch(sub, "name")}"] = true if sub.is_a?(Hash)
          end
        end
        names
      end

      def claim_device_id(device)
        [fetch(device, "driver").to_s, fetch(device, "pool").to_s, fetch(device, "device").to_s, fetch(device, "shareID").to_s]
      end

      # gatherAllocatedDevices.
      def claim_allocated_devices(allocation)
        return {} unless allocation.is_a?(Hash)

        Array(fetch(fetch(allocation, "devices") || {}, "results")).each_with_object({}) do |result, set|
          set[claim_device_id(result)] = true if result.is_a?(Hash)
        end
      end

      # validateDeviceStatus.
      def claim_device_status_errors(device, path, allocated)
        issues = []
        issues.concat(claim_driver_name_errors(fetch(device, "driver"), path + ["driver"]))
        issues.concat(claim_pool_name_errors(fetch(device, "pool"), path + ["pool"]))
        issues.concat(claim_device_name_errors(fetch(device, "device"), path + ["device"]))
        share = fetch(device, "shareID")
        issues.concat(claim_uid_errors(share, path + ["shareID"])) unless share.nil?
        unless allocated[claim_device_id(device)]
          driver, pool, name, shared = claim_device_id(device)
          id = shared.empty? ? "#{driver}/#{pool}/#{name}" : "#{driver}/#{pool}/#{name}/#{shared}"
          issues << issue(path, :invalid, "must be an allocated device in the claim (#{id.inspect})")
        end
        conditions = Array(fetch(device, "conditions"))
        if conditions.length > DEVICE_STATUS_MAX_CONDITIONS
          issues << issue(path + ["conditions"], :too_many, "must have at most #{DEVICE_STATUS_MAX_CONDITIONS} items")
        end
        issues.concat(meta_conditions_errors(conditions, path + ["conditions"]))
        data = fetch(device, "data")
        issues.concat(claim_raw_extension_errors(data, path + ["data"], DEVICE_STATUS_DATA_MAX)) unless data.nil?
        network = fetch(device, "networkData")
        issues.concat(claim_network_errors(network, path + ["networkData"])) if network.is_a?(Hash)
        issues
      end

      # metav1validation.ValidateConditions.
      def meta_conditions_errors(conditions, path)
        issues = []
        types = {}
        conditions.each_with_index do |condition, index|
          condition = {} unless condition.is_a?(Hash)
          item = path + [index.to_s]
          type = fetch(condition, "type").to_s
          issues << issue(item + ["type"], :duplicate, "") if types[type]
          types[type] = true
          issues.concat(invalid_messages(item + ["type"], qualified_name_messages(type)))
          unless %w[True False Unknown].include?(fetch(condition, "status").to_s)
            issues << issue(item + ["status"], :unsupported, 'supported values: "False", "True", "Unknown"')
          end
          observed = fetch(condition, "observedGeneration")
          if observed.is_a?(Integer) && observed.negative?
            issues << issue(item + ["observedGeneration"], :invalid,
                            "must be greater than or equal to zero")
          end
          issues << issue(item + ["lastTransitionTime"], :required, "") if blank?(fetch(condition, "lastTransitionTime"))
          reason = fetch(condition, "reason").to_s
          if reason.empty?
            issues << issue(item + ["reason"], :required, "")
          else
            issues << issue(item + ["reason"], :invalid, CONDITION_REASON_MSG) unless reason.match?(CONDITION_REASON)
            issues << issue(item + ["reason"], :too_long, "may not be more than 1024 bytes") if reason.bytesize > 1024
          end
          message = fetch(condition, "message").to_s
          issues << issue(item + ["message"], :too_long, "may not be more than 32768 bytes") if message.bytesize > 32 * 1024
        end
        issues
      end

      # validateRawExtension (not stored): a JSON object within the limit.
      def claim_raw_extension_errors(data, path, maximum)
        raw = data.is_a?(String) ? data : JSON.generate(data)
        return [issue(path, :required, "")] if raw.empty? || data.nil?
        return [issue(path, :too_long, "may not be more than #{maximum} bytes")] if raw.bytesize > maximum

        value = data.is_a?(String) ? JSON.parse(data) : data
        return [issue(path, :required, "")] if value.nil?
        return [issue(path, :invalid, "must be a valid JSON object")] unless value.is_a?(Hash)

        []
      rescue JSON::ParserError => error
        [issue(path, :invalid, "error parsing data as JSON: #{error.message}")]
      end

      # validateNetworkDeviceData.
      def claim_network_errors(network, path)
        issues = []
        interface = fetch(network, "interfaceName").to_s
        if interface.bytesize > NETWORK_INTERFACE_MAX
          issues << issue(path + ["interfaceName"], :too_long, "may not be more than #{NETWORK_INTERFACE_MAX} bytes")
        end
        hardware = fetch(network, "hardwareAddress").to_s
        if hardware.bytesize > NETWORK_HARDWARE_MAX
          issues << issue(path + ["hardwareAddress"], :too_long, "may not be more than #{NETWORK_HARDWARE_MAX} bytes")
        end
        ips = Array(fetch(network, "ips"))
        issues << issue(path + ["ips"], :too_many, "must have at most #{NETWORK_MAX_IPS} items") if ips.length > NETWORK_MAX_IPS
        seen = {}
        ips.each_with_index do |address, index|
          item = path + ["ips", index.to_s]
          issues << issue(item, :duplicate, "") if seen[address]
          seen[address] = true
          issues.concat(invalid_messages(item, interface_address_messages(address.to_s)))
        end
        issues
      end

      # IsValidInterfaceAddress: an IP address with a prefix length, in
      # canonical form.
      def interface_address_messages(value)
        address_text, slash, length_text = value.rpartition("/")
        if slash.empty? || !length_text.match?(/\A\d+\z/)
          return ["must be a valid address in CIDR form, (e.g. 10.9.8.7/24 or 2001:db8::1/64)"]
        end

        address = IPAddr.new(address_text)
        maximum = address.ipv4? ? 32 : 128
        return ["must be a valid address in CIDR form, (e.g. 10.9.8.7/24 or 2001:db8::1/64)"] if length_text.to_i > maximum

        canonical = "#{address}/#{length_text.to_i}"
        canonical == value ? [] : ["must be in canonical form (#{canonical.inspect})"]
      rescue IPAddr::Error, ArgumentError
        ["must be a valid address in CIDR form, (e.g. 10.9.8.7/24 or 2001:db8::1/64)"]
      end

      # validateAllocationResult.
      def claim_allocation_errors(allocation, request_names)
        issues = []
        devices = fetch(allocation, "devices")
        devices = {} unless devices.is_a?(Hash)
        results = Array(fetch(devices, "results"))
        path = %w[status allocation devices results]
        issues << issue(path, :too_many, "must have at most #{ALLOCATION_RESULTS_MAX} items") if results.length > ALLOCATION_RESULTS_MAX
        results.each_with_index do |result, index|
          result = {} unless result.is_a?(Hash)
          item = path + [index.to_s]
          issues.concat(claim_request_ref_errors(fetch(result, "request").to_s, item + ["request"], request_names))
          issues.concat(claim_driver_name_errors(fetch(result, "driver"), item + ["driver"]))
          issues.concat(claim_pool_name_errors(fetch(result, "pool"), item + ["pool"]))
          issues.concat(claim_device_name_errors(fetch(result, "device"), item + ["device"]))
          %w[bindingConditions bindingFailureConditions].each do |field|
            values = Array(fetch(result, field))
            if values.length > BINDING_CONDITIONS_MAX
              issues << issue(item + [field], :too_many,
                              "must have at most #{BINDING_CONDITIONS_MAX} items")
            end
            values.each_with_index do |value, position|
              issues.concat(invalid_messages(item + [field, position.to_s], qualified_name_messages(value.to_s)))
              issues << issue(item + [field, position.to_s], :duplicate, "") if values[0...position].include?(value)
            end
          end
          share = fetch(result, "shareID")
          issues.concat(claim_uid_errors(share, item + ["shareID"])) unless share.nil?
        end
        Array(fetch(devices, "config")).each_with_index do |config, index|
          config = {} unless config.is_a?(Hash)
          item = %w[status allocation devices config] + [index.to_s]
          source = fetch(config, "source").to_s
          if source.empty?
            issues << issue(item + ["source"], :required, "")
          elsif !%w[FromClass FromClaim].include?(source)
            issues << issue(item + ["source"], :unsupported, 'supported values: "FromClaim", "FromClass"')
          end
          Array(fetch(config, "requests")).each_with_index do |name, position|
            issues.concat(claim_request_ref_errors(name.to_s, item + ["requests", position.to_s], request_names))
          end
          opaque = fetch(config, "opaque")
          if opaque.is_a?(Hash)
            issues.concat(claim_driver_name_errors(fetch(opaque, "driver"), item + %w[opaque driver]))
          else
            issues << issue(item + ["opaque"], :required, "")
          end
        end
        issues
      end

      def claim_request_ref_errors(name, path, request_names)
        message = "must be the name of a request in the claim or the name of a request and a subrequest separated by '/'"
        segments = name.split("/", -1)
        return [issue(path, :invalid, message)] if segments.length > 2

        issues = segments.flat_map { |segment| invalid_messages(path, dns1123_label_messages(segment)) }
        issues << issue(path, :invalid, message) unless request_names[name]
        issues
      end

      # ValidateCSIDriverName.
      def claim_driver_name_errors(name, path)
        name = name.to_s
        return [issue(path, :required, "")] if name.empty?

        issues = []
        issues << issue(path, :too_long, "may not be more than 63 bytes") if name.length > 63
        issues.concat(invalid_messages(path, dns1123_subdomain_messages(name.downcase)))
        issues
      end

      # validatePoolName: "/"-separated DNS subdomains.
      def claim_pool_name_errors(name, path)
        name = name.to_s
        return [issue(path, :required, "")] if name.empty?

        issues = []
        issues << issue(path, :too_long, "may not be more than 253 bytes") if name.length > 253
        name.split("/", -1).each { |part| issues.concat(invalid_messages(path, dns1123_subdomain_messages(part))) }
        issues
      end

      def claim_device_name_errors(name, path)
        name = name.to_s
        return [issue(path, :required, "")] if name.empty?

        invalid_messages(path, dns1123_label_messages(name))
      end

      def claim_uid_errors(uid, path)
        uid = uid.to_s
        unless uid.length == 36 && uid.match?(UUID)
          return [issue(path, :invalid,
                        "error validating uid: invalid UUID length: #{uid.length}")]
        end
        return [] if uid == uid.downcase

        [issue(path, :invalid,
               "uid must be in RFC 4122 normalized form, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` with lowercase hexadecimal characters")]
      end
    end
  end
end
