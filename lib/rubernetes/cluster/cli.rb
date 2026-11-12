# frozen_string_literal: true

require "optparse"
require_relative "../cluster"

module Rubernetes
  module Cluster
    # `rubectl cluster ...`: a cluster on this host with one command.
    class CLI
      COMMANDS = %w[up start down delete scale status kubeconfig].freeze
      IP_FAMILIES = {"ipv4" => %w[ipv4], "ipv6" => %w[ipv6], "dual" => %w[ipv4 ipv6]}.freeze
      USAGE = <<~TEXT
        Usage: rubectl cluster COMMAND [options]

          up          provision a new cluster and wait until its nodes are Ready
          start       restart a provisioned cluster (after a reboot or `down`); nothing is reissued
          down        stop the cluster's processes; its state stays on disk
          delete      stop the cluster and remove its state, mounts, bridges and firewall rules
          scale       add control nodes to the running cluster (--controls N); the datastore stays available
          status      list the cluster's processes
          kubeconfig  print the admin kubeconfig path

      TEXT

      def self.run(argv, stdout: $stdout, stderr: $stderr)
        new(stdout: stdout, stderr: stderr).run(argv)
      end

      def initialize(stdout:, stderr:)
        @stdout = stdout
        @stderr = stderr
      end

      def run(argv)
        arguments = argv.dup
        options = {name: "default", root: nil, controls: 1, workers: 1, ip_families: %w[ipv4], identities: :admin,
                   extensions: false, storage: true, force: false, json: false, help: false}
        parser = option_parser(options)
        parser.parse!(arguments)
        command = arguments.shift
        return usage(parser, @stdout, 0) if options[:help]
        return usage(parser, @stderr, 64) unless COMMANDS.include?(command) && arguments.empty?

        public_send(command, provisioner(options), options)
      rescue OptionParser::ParseError => error
        @stderr.puts("rubectl cluster: #{error.message}")
        64
      rescue Error, Client::Error, SystemCallError => error
        @stderr.puts("rubectl cluster: #{error.message}")
        1
      end

      def up(cluster, options)
        raise Error, "bringing a cluster up needs root (network namespaces, cgroups, mounts)" unless Process.uid.zero?

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        descriptor = cluster.up
        report(descriptor, options) do
          seconds = (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round
          @stdout.puts("cluster #{cluster.cluster_name.inspect} is ready: #{cluster.control_ids.length} control, " \
                       "#{cluster.worker_ids.length} worker (#{seconds}s)")
          @stdout.puts("  export KUBECONFIG=#{cluster.kubeconfig}")
        end
      end

      def start(cluster, options)
        descriptor = cluster.start
        report(descriptor, options) { @stdout.puts("cluster #{cluster.cluster_name.inspect} is running again") }
      end

      def down(cluster, options)
        stopped = cluster.down
        report({"stopped" => stopped}, options) { @stdout.puts("stopped #{stopped.length} processes; state kept in #{cluster.root}") }
      end

      def scale(cluster, options)
        descriptor = cluster.scale(controls: options[:controls])
        report(descriptor, options) do
          servers = descriptor.fetch("processes").count { |process| process.fetch("executable") == "rubernetes-apiserver" }
          @stdout.puts("cluster #{cluster.cluster_name.inspect} has #{servers} control nodes")
        end
      end

      def delete(cluster, options)
        stopped = cluster.delete
        report({"stopped" => stopped, "removed" => cluster.root}, options) { @stdout.puts("cluster #{cluster.cluster_name.inspect} is gone") }
      end

      def status(cluster, options)
        processes = cluster.status
        report({"root" => cluster.root, "processes" => processes}, options) do
          @stdout.puts("no provisioned cluster at #{cluster.root}") if processes.empty?
          processes.each do |process|
            @stdout.puts(format("%-28<name>s %-8<state>s pid %<pid>d", name: process.fetch("name"), pid: process.fetch("pid"),
                                                                       state: process.fetch("alive") ? "running" : "stopped"))
          end
        end
        processes.any? && processes.all? { |process| process.fetch("alive") } ? 0 : 1
      end

      def kubeconfig(cluster, _options)
        @stdout.puts(cluster.kubeconfig)
        File.file?(cluster.kubeconfig) ? 0 : 1
      end

      private

      def report(document, options)
        options[:json] ? @stdout.puts(JSON.pretty_generate(document)) : yield
        0
      end

      def provisioner(options)
        Provisioner.new(root: options[:root] || File.join(DEFAULT_STATE_DIR, options[:name]), name: options[:name],
                        controls: options[:controls], workers: options[:workers], ip_families: options[:ip_families],
                        identities: options[:identities], extensions: options[:extensions], storage: options[:storage],
                        force: options[:force])
      end

      def usage(parser, io, status)
        io.puts(USAGE)
        io.puts(parser.summarize)
        status
      end

      def option_parser(options)
        OptionParser.new do |parser|
          parser.on("--name NAME", "cluster name (default: default)") { |value| options[:name] = value }
          parser.on("--root DIR", "cluster directory (default: #{DEFAULT_STATE_DIR}/NAME)") { |value| options[:root] = value }
          parser.on("--controls N", Integer, "up: control nodes, each an API server and a raft voter (default: 1)") { |value| options[:controls] = value }
          parser.on("--workers N", Integer, "up: worker nodes (default: 1)") { |value| options[:workers] = value }
          parser.on("--ha", "up: 3 control nodes and 3 workers") { options.merge!(controls: 3, workers: 3) }
          parser.on("--ip-family FAMILY", IP_FAMILIES, "up: ipv4, ipv6 or dual (default: ipv4)") { |value| options[:ip_families] = value }
          parser.on("--identities MODE", Provisioner::IDENTITY_MODES,
                    "up: admin, components or bootstrap (default: admin)") { |value| options[:identities] = value }
          parser.on("--extensions", "up: let the components load Extension objects (Ruby run inside them)") { options[:extensions] = true }
          parser.on("--no-storage", "up: no default StorageClass and no hostPath provisioner") { options[:storage] = false }
          parser.on("--force", "up: take over bridges and workloads of another live cluster") { options[:force] = true }
          parser.on("-o", "--output FORMAT", %w[json text], "json or text (default: text)") { |value| options[:json] = value == "json" }
          parser.on("-h", "--help") { options[:help] = true }
        end
      end
    end
  end
end
