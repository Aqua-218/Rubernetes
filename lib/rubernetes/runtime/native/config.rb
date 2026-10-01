# frozen_string_literal: true

# Native backend configuration is pure data.  In particular, selecting a host
# or kernel-isolation profile is an explicit act; an incomplete host probe can
# never silently downgrade to an in-process fake.

require "digest"
require "json"
require "rbconfig"

module Rubernetes
  module Runtime
    class Native
      class Configuration
        PROFILES = %i[pure fake_io host_integration kernel_isolation l3].freeze
        RUNTIME_CLASS = "rubernetes-native"
        DEFAULT_SANDBOX_ROOT = "/var/lib/rubernetes/native"
        DEFAULT_CGROUP_ROOT = "/sys/fs/cgroup"
        DEFAULT_LOG_ROOT = "/var/log/rubernetes/native"
        DEFAULT_JOURNAL_PATH = "/var/lib/rubernetes/native/ledger.jsonl"

        attr_reader :profile, :sandbox_root, :cgroup_root, :log_root, :journal_path,
                    :runtime_class, :architecture, :host_integration, :l3,
                    :security_context, :capabilities, :limits, :image, :network,
                    :namespace, :max_log_bytes, :max_log_files, :strict,
                    :memory_qos, :pod_pids_limit, :userns_allocation_path, :seccomp_root

        def initialize(profile: :pure, sandbox_root: DEFAULT_SANDBOX_ROOT, cgroup_root: DEFAULT_CGROUP_ROOT,
                       log_root: DEFAULT_LOG_ROOT, journal_path: DEFAULT_JOURNAL_PATH,
                       runtime_class: RUNTIME_CLASS, architecture: nil, host_integration: false,
                       l3: false, security_context: {}, capabilities: {}, limits: {}, image: {},
                       network: {}, namespace: {}, max_log_bytes: 10 * 1024 * 1024,
                       max_log_files: 5, strict: true, memory_qos: false, pod_pids_limit: nil,
                       userns_allocation_path: nil, seccomp_root: nil, **extra)
          @profile = normalize_profile(profile)
          @seccomp_root = seccomp_root.nil? ? nil : File.expand_path(String(seccomp_root)).freeze
          @sandbox_root = normalize_absolute_path(sandbox_root, "sandbox_root")
          @cgroup_root = normalize_absolute_path(cgroup_root, "cgroup_root")
          @log_root = normalize_absolute_path(log_root, "log_root")
          @journal_path = normalize_absolute_path(journal_path, "journal_path")
          @runtime_class = String(runtime_class).freeze
          @architecture = normalize_architecture(architecture)
          @host_integration = host_integration == true
          @l3 = l3 == true
          @security_context = immutable(security_context.respond_to?(:to_h) ? security_context.to_h : {})
          @capabilities = immutable(capabilities.respond_to?(:to_h) ? capabilities.to_h : {})
          @limits = immutable(limits.respond_to?(:to_h) ? limits.to_h : {})
          @image = immutable(image.respond_to?(:to_h) ? image.to_h : {})
          @network = immutable(network.respond_to?(:to_h) ? network.to_h : {})
          @namespace = immutable(namespace.respond_to?(:to_h) ? namespace.to_h : {})
          @max_log_bytes = Integer(max_log_bytes)
          @max_log_files = Integer(max_log_files)
          @strict = strict == true
          # MemoryQoS mirrors the v1.36.2 feature gate (alpha, default off):
          # memory.min/low/high are written only when explicitly enabled.
          @memory_qos = memory_qos == true
          @pod_pids_limit = pod_pids_limit.nil? ? nil : Integer(pod_pids_limit)
          @userns_allocation_path = normalize_absolute_path(
            userns_allocation_path || File.join(File.dirname(@journal_path), "userns-allocations.json"), "userns_allocation_path"
          )
          @extra = immutable(extra)
          validate!
          freeze
        end

        def self.from(value = nil, profile: nil, **overrides)
          return value if value.is_a?(self) && profile.nil? && overrides.empty?

          input = value.respond_to?(:to_h) ? value.to_h.dup : {}
          input[:profile] = profile if profile
          input.merge!(overrides)
          new(**symbolize_known(input))
        rescue ArgumentError, TypeError => error
          raise ConfigurationError, "invalid native runtime configuration: #{error.message}"
        end

        def to_h
          {
            "profile" => profile.to_s,
            "sandbox_root" => sandbox_root,
            "cgroup_root" => cgroup_root,
            "log_root" => log_root,
            "journal_path" => journal_path,
            "runtime_class" => runtime_class,
            "architecture" => architecture,
            "host_integration" => host_integration,
            "l3" => l3,
            "security_context" => security_context,
            "capabilities" => capabilities,
            "limits" => limits,
            "image" => image,
            "network" => network,
            "namespace" => namespace,
            "max_log_bytes" => max_log_bytes,
            "max_log_files" => max_log_files,
            "strict" => strict,
            "memory_qos" => memory_qos,
            "pod_pids_limit" => pod_pids_limit,
            "userns_allocation_path" => userns_allocation_path,
            "seccomp_root" => seccomp_root
          }.merge(@extra)
        end

        def digest
          Digest::SHA256.hexdigest(canonical_json(to_h))
        end

        def host_profile?
          %i[host_integration kernel_isolation l3].include?(profile)
        end

        def kernel_profile?
          %i[kernel_isolation l3].include?(profile)
        end

        def pure_profile?
          %i[pure fake_io].include?(profile)
        end

        def validate!
          if host_integration && pure_profile?
            raise ConfigurationError, "host_integration requires an explicit host_integration, kernel_isolation, or l3 profile"
          end
          raise ConfigurationError, "l3 requires the explicit kernel_isolation or l3 profile" if l3 && !kernel_profile?
          raise ConfigurationError, "the l3 profile requires l3: true" if profile == :l3 && !l3
          raise ConfigurationError, "unsupported Native runtime class #{runtime_class.inspect}" unless runtime_class == RUNTIME_CLASS
          raise ConfigurationError, "max_log_bytes must be positive" unless max_log_bytes.positive?
          raise ConfigurationError, "max_log_files must be between 1 and 64" unless max_log_files.between?(1, 64)
          raise ConfigurationError, "pod_pids_limit must be positive" if pod_pids_limit && !pod_pids_limit.positive?

          validate_path_relationships!
          validate_limits!
          true
        end

        def self.symbolize_known(input)
          known = %i[profile sandbox_root cgroup_root log_root journal_path runtime_class architecture host_integration l3 security_context
                     capabilities limits image network namespace max_log_bytes max_log_files strict memory_qos pod_pids_limit userns_allocation_path
                     seccomp_root]
          input.each_with_object({}) do |(key, value), result|
            symbol = key.to_sym
            result[symbol] = value if known.include?(symbol)
          end
        end

        private

        def normalize_profile(value)
          profile = String(value).downcase.tr("-", "_").to_sym
          return profile if PROFILES.include?(profile)

          raise ConfigurationError, "profile must be one of #{PROFILES.join(", ")}"
        end

        def normalize_absolute_path(value, name)
          path = File.expand_path(String(value))
          raise ConfigurationError, "#{name} must be an absolute path" unless path.start_with?("/")
          raise ConfigurationError, "#{name} must not contain NUL" if path.include?("\0")

          path.freeze
        end

        def normalize_architecture(value)
          key = String(value || RbConfig::CONFIG.fetch("host_cpu")).downcase
          return "x86_64" if %w[x86_64 amd64].include?(key)
          return "aarch64" if %w[aarch64 arm64].include?(key)

          raise ConfigurationError, "unsupported Native architecture #{value.inspect}"
        end

        def validate_path_relationships!
          roots = [sandbox_root, log_root, journal_path].map { |path| File.expand_path(path) }
          roots.combination(2).each do |left, right|
            next unless left == right

            raise ConfigurationError, "sandbox, log, and journal paths must not alias one another"
          end
        end

        def validate_limits!
          limits.each do |key, value|
            next if value.nil?
            raise ConfigurationError, "resource limit #{key.inspect} must not be negative" if value.is_a?(Numeric) && value.negative?
          end
        end

        def immutable(value)
          copied = case value
                   when Hash then value.to_h { |key, child| [String(key), immutable(child)] }
                   when Array then value.map { |child| immutable(child) }
                   else value
                   end
          copied.freeze
        end

        def canonical_json(value)
          case value
          when Hash
            JSON.generate(value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
              source = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
              result[key] = canonical_json(value.fetch(source))
            end)
          when Array then "[#{value.map { |child| canonical_json(child) }.join(",")}]"
          else JSON.generate(value)
          end
        end
      end

      Config = Configuration unless const_defined?(:Config, false)
    end
  end
end
