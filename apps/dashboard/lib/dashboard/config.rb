# frozen_string_literal: true

require "yaml"
require "json"
require "socket"
require "uri"

module Dashboard
  # Runtime configuration, from the environment with sensible defaults for a
  # cluster brought up by tools/conformance/cluster.rb.
  module Config
    DEFAULT_CLUSTER_ROOT = "/srv/rbn-app/linux-amd64-ipv4-native"

    module_function

    def cluster_root
      ENV.fetch("RUBERNETES_CLUSTER_ROOT", DEFAULT_CLUSTER_ROOT)
    end

    def kubeconfig_path
      ENV.fetch("RUBERNETES_KUBECONFIG") { File.join(cluster_root, "kubeconfig") }
    end

    def cluster_json_path
      ENV.fetch("RUBERNETES_CLUSTER_JSON") { File.join(cluster_root, "cluster.json") }
    end

    def cluster_json
      path = cluster_json_path
      File.file?(path) ? JSON.parse(File.read(path)) : {}
    rescue JSON::ParserError
      {}
    end

    def data_dir
      ENV.fetch("DASHBOARD_DATA_DIR") { File.expand_path("../../data", __dir__) }
    end

    def scrape_interval_seconds
      Float(ENV.fetch("DASHBOARD_SCRAPE_INTERVAL", "15"))
    end

    def scrape_timeout_seconds
      Float(ENV.fetch("DASHBOARD_SCRAPE_TIMEOUT", "10"))
    end

    def evaluation_interval_seconds
      Float(ENV.fetch("DASHBOARD_EVALUATION_INTERVAL", scrape_interval_seconds.to_s))
    end

    def retention_ms
      Integer(duration_seconds(ENV.fetch("DASHBOARD_RETENTION", "15d")) * 1000)
    end

    def block_range_ms
      Integer(duration_seconds(ENV.fetch("DASHBOARD_BLOCK_RANGE", "2h")) * 1000)
    end

    def rules_path
      ENV.fetch("DASHBOARD_RULES") { File.expand_path("../../config/rules.yml", __dir__) }
    end

    def alert_webhook_url
      value = ENV.fetch("DASHBOARD_ALERT_WEBHOOK", "")
      value.empty? ? nil : value
    end

    def password
      value = ENV.fetch("DASHBOARD_PASSWORD", "")
      value.empty? ? nil : value
    end

    def writes_allowed?
      ENV.fetch("DASHBOARD_ALLOW_WRITES", "1") != "0"
    end

    def collector_enabled?
      ENV.fetch("DASHBOARD_COLLECTOR", "1") != "0"
    end

    def external_url
      ENV.fetch("DASHBOARD_EXTERNAL_URL", "")
    end

    # Host names Rails' host authorization accepts (DNS-rebinding guard).
    # DASHBOARD_HOSTS is comma separated; ".example.com" also matches every
    # subdomain, like Rails' own config.hosts.  Empty means "any host".
    # The default admits the bind address, loopback, the machine's names and
    # the host of DASHBOARD_EXTERNAL_URL, which is how the Ingress reaches it.
    def allowed_hosts
      text = ENV.fetch("DASHBOARD_HOSTS") { default_hosts.join(",") }
      text.split(",").map(&:strip).reject(&:empty?)
    end

    def default_hosts
      hosts = ["localhost", "127.0.0.1", "[::1]", ENV.fetch("DASHBOARD_BIND", "")]
      hosts << Socket.gethostname rescue nil
      hosts << ".#{Socket.gethostname}" rescue nil
      unless external_url.empty?
        begin
          host = URI.parse(external_url).host
          hosts << host if host
        rescue URI::InvalidURIError
          nil
        end
      end
      hosts.compact.reject(&:empty?).uniq
    end

    # "15d", "2h", "90s", "500ms"
    def duration_seconds(text)
      match = /\A(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)?\z/.match(text.to_s.strip)
      raise ArgumentError, "bad duration #{text.inspect}" unless match

      value = Float(match[1])
      case match[2]
      when "ms" then value / 1000
      when nil, "s" then value
      when "m" then value * 60
      when "h" then value * 3600
      when "d" then value * 86_400
      when "w" then value * 7 * 86_400
      when "y" then value * 365 * 86_400
      end
    end
  end
end
