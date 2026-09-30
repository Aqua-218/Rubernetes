# frozen_string_literal: true

require "json"
require "optparse"
require_relative "../version"
require_relative "assembler"
require_relative "config"
require_relative "runner"

module Rubernetes
  module Bootstrap
    class CLI
      EX_USAGE = 64
      EX_UNAVAILABLE = 69
      DAEMONS = (Config::PROCESS_NAMES - ["rubectl"]).freeze

      def self.run(process_name:, argv:, stdout: $stdout, stderr: $stderr)
        new(process_name: process_name, stdout: stdout, stderr: stderr).run(argv)
      end

      def initialize(process_name:, stdout:, stderr:)
        @process_name = process_name
        @stdout = stdout
        @stderr = stderr
      end

      def run(argv)
        Config.validate_process_name!(@process_name)
        return run_rubectl(argv) if @process_name == "rubectl" && !argv.include?("--check-config")

        options = {config_path: nil, check_config: false}
        parser = option_parser(options)
        arguments = argv.dup
        parser.parse!(arguments)

        if options[:help]
          @stdout.puts(parser)
          return 0
        end
        if options[:version]
          @stdout.puts("#{@process_name} #{Rubernetes::VERSION}")
          return 0
        end
        unless arguments.empty?
          @stderr.puts("#{@process_name}: unexpected arguments: #{arguments.join(" ")}")
          return EX_USAGE
        end

        assembly = Assembler.new(
          process_name: @process_name,
          config_path: options[:config_path],
          log_io: @stderr
        ).build
        if options[:check_config]
          @stdout.puts(JSON.generate(process: @process_name, valid: true, config: assembly.config.to_h))
          assembly.shutdown.close
          return 0
        end
        Runner.new(assembly: assembly).run
      rescue OptionParser::ParseError, Config::Error => error
        @stderr.puts("#{@process_name}: #{error.message}")
        EX_USAGE
      end

      private

      def run_rubectl(argv)
        require_relative "../rubectl"

        # M0 exposed --config on every executable. Keep that spelling as a
        # side-effect-free compatibility alias for rubectl's --kubeconfig.
        arguments = argv.map do |argument|
          argument == "--config" ? "--kubeconfig" : argument.sub(/\A--config=/, "--kubeconfig=")
        end
        Rubernetes::Rubectl::CLI.run(arguments, stdout: @stdout, stderr: @stderr)
      end

      def option_parser(options)
        OptionParser.new do |parser|
          parser.banner = "Usage: #{@process_name} [options]"
          parser.on("-c", "--config PATH", "load configuration from PATH") { |path| options[:config_path] = path }
          parser.on("--check-config", "validate configuration and exit") { options[:check_config] = true }
          parser.on("-v", "--version", "print version and exit") { options[:version] = true }
          parser.on("-h", "--help", "show this help and exit") { options[:help] = true }
        end
      end
    end
  end
end
