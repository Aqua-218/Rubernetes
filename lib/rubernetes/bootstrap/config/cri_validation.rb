# frozen_string_literal: true

require_relative "../../runtime/cpu_quota"

module Rubernetes
  module Bootstrap
    class Config
      module CRIValidation
        private

        def validate_agent_runtime_limits!(process)
          validate_agent_cri!(process.fetch("cri")) if process.key?("cri")
          validate_image_pull_limits!(process)
          validate_cpu_quota!(process)
          validate_single_process_oom_kill!(process["single_process_oom_kill"])
          validate_absolute_path!(process["pod_logs_dir"], "rubernetes-agent.pod_logs_dir") if process.key?("pod_logs_dir")
          if process.key?("pod_pids_limit")
            limit = process.fetch("pod_pids_limit")
            unless limit.is_a?(Integer) && (limit == -1 || limit.between?(1, (2**63) - 1))
              raise Error, "rubernetes-agent.pod_pids_limit must be -1 or a positive int64"
            end
          end
          if process.key?("container_log_max_size") && parse_container_log_size!(process.fetch("container_log_max_size"), "rubernetes-agent") <= 0
            raise Error, "rubernetes-agent.container_log_max_size must be a positive size"
          end
          return unless process.key?("container_log_max_files")

          files = process.fetch("container_log_max_files")
          raise Error, "rubernetes-agent.container_log_max_files must be an integer between 2 and 64" unless files.is_a?(Integer) && files.between?(2, 64)
        end

        def validate_cpu_quota!(process)
          enabled, period = process.values_at("cpu_cfs_quota", "cpu_cfs_quota_period_seconds")
          raise Error, "rubernetes-agent.cpu_cfs_quota must be a boolean" unless [nil, true, false].include?(enabled)
          return if period.nil?

          context = "rubernetes-agent.cpu_cfs_quota_period_seconds"
          if process.dig("feature_gates", Runtime::CPUQuota::CUSTOM_PERIOD_GATE) == false && period != Runtime::CPUQuota::DEFAULT_SECONDS
            raise Error, "#{context} requires feature gate #{Runtime::CPUQuota::CUSTOM_PERIOD_GATE}"
          end
          return if period.is_a?(Numeric) && period.between?(0.001, 1)

          raise Error, "#{context} must be between 1ms and 1s, inclusive"
        end

        def validate_single_process_oom_kill!(value)
          return if value.nil?

          name = "rubernetes-agent.single_process_oom_kill"
          raise Error, "#{name} must be a boolean or null" unless [true, false].include?(value)
          raise Error, "#{name} is supported only on Linux" unless RUBY_PLATFORM.include?("linux")
          return if value || File.file?("/sys/fs/cgroup/cgroup.controllers")

          raise Error, "#{name} cannot be false on cgroup v1"
        end

        def validate_image_pull_limits!(process)
          serialize, limit = process.values_at("serialize_image_pulls", "max_parallel_image_pulls")
          raise Error, "rubernetes-agent.serialize_image_pulls must be a boolean" unless [nil, true, false].include?(serialize)
          return if limit.nil?

          raise Error, "rubernetes-agent.max_parallel_image_pulls must be a positive int32" unless limit.is_a?(Integer) && limit.between?(1, (2**31) - 1)
          return unless serialize == true && limit > 1

          raise Error, "rubernetes-agent.max_parallel_image_pulls cannot exceed 1 when serialize_image_pulls is true"
        end

        def validate_agent_cri!(section)
          validate_mapping!(section, "rubernetes-agent.cri")
          reject_unknown_keys!(section, AGENT_CRI_KEYS, "rubernetes-agent.cri")
          raise Error, "rubernetes-agent.cri.enabled must be a boolean" if section.key?("enabled") && ![true, false].include?(section["enabled"])

          %w[endpoint log_root cgroup_parent].each do |key|
            next unless section.key?(key)
            next if section[key].is_a?(String) && section[key].delete_prefix("unix://").start_with?("/")

            raise Error, "rubernetes-agent.cri.#{key} must be an absolute path"
          end
          raise Error, "rubernetes-agent.cri.endpoint is required when cri is enabled" if section["enabled"] == true && !section.key?("endpoint")

          handlers = section.fetch("handlers", {"cri" => ""})
          unless handlers.is_a?(Hash) && handlers.all? { |name, handler| name.is_a?(String) && !name.empty? && handler.is_a?(String) }
            raise Error, "rubernetes-agent.cri.handlers must map handler names to CRI runtime handlers"
          end
          raise Error, "rubernetes-agent.cri.handlers cannot take over the rubernetes-native handler" if handlers.key?("rubernetes-native")
          if section.key?("default_handler") && !(section["enabled"] == true && handlers.key?(section["default_handler"]))
            raise Error, "rubernetes-agent.cri.default_handler must name a configured handler with CRI enabled"
          end
          if section.key?("container_log_max_files") && !(section["container_log_max_files"].is_a?(Integer) && section["container_log_max_files"] >= 2)
            raise Error, "rubernetes-agent.cri.container_log_max_files must be an integer of at least 2"
          end

          parse_container_log_size!(section.fetch("container_log_max_size"), "rubernetes-agent.cri") if section.key?("container_log_max_size")
          validate_container_log_workers!(section.fetch("container_log_max_workers")) if section.key?("container_log_max_workers")
          %w[timeout_seconds container_log_monitor_interval_seconds].each do |key|
            validate_positive_number!(section.fetch(key), "rubernetes-agent.cri.#{key}") if section.key?(key)
          end
        end

        def validate_container_log_workers!(workers)
          require_relative "../../runtime/cri/log_manager"
          return if workers.is_a?(Integer) && workers.between?(1, Runtime::CRI::LogManager::MAX_WORKERS)

          raise Error, "rubernetes-agent.cri.container_log_max_workers must be an int32 greater than or equal to 1"
        end

        def parse_container_log_size!(value, section)
          require_relative "../../runtime/cri/log_manager"
          Runtime::CRI::LogManager.parse_max_size(value)
        rescue Schema::Quantity::ParseError => error
          raise Error, "#{section}.container_log_max_size must be an int64 byte count: #{error.message}"
        end
      end
    end
  end
end
