# frozen_string_literal: true

require_relative "k7_cluster_driver"

module Conformance
  module K3WorkerRestart
    PROXY_ENV = %w[HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy].freeze

    private

    def with_agent_stopped(worker)
      pid = K7ClusterDriver.pid_of(worker)
      environment = File.binread("/proc/#{pid}/environ").split("\0").to_h { |entry| entry.split("=", 2) }
      K7ClusterDriver.stop!(worker, signal: "KILL")
      yield
    ensure
      if worker["_argv"] && !K7ClusterDriver.pid_of(worker)
        since = Time.now.utc
        worker.fetch("_env").merge!((environment || {}).slice(*PROXY_ENV))
        K7ClusterDriver.start!(worker)
        K7ClusterDriver.wait_for_component!(worker, since)
      end
    end

    def mounts_below(root)
      File.foreach("/proc/self/mountinfo").filter_map do |line|
        mount = mountinfo_target(line)
        mount if mount.start_with?("#{root}/")
      end.sort
    end

    def mountinfo_target(line)
      line.split(" ", 6).fetch(4).gsub(/\\([0-7]{3})/) { Regexp.last_match(1).oct.chr }
    end
  end
end
