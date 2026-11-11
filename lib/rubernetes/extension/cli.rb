# frozen_string_literal: true

require "json"

require_relative "../client"
require_relative "../extension"

module Rubernetes
  module Extension
    # `rubectl extension ...`: extensions as files on the way in, and as what
    # each component made of them on the way out.
    class CLI
      USAGE = <<~TEXT
        Usage: rubectl extension COMMAND

          apply FILE.rb...   load the file, store it as an Extension and report what each component did with it
          check FILE.rb...   load the file here and list what it declares; nothing is sent to the cluster
          list               the stored extensions and their state in each component
          delete NAME...     remove extensions; their plugins, hooks and controllers stop at once
      TEXT
      COMPONENTS = %w[scheduler admission controller].freeze
      # How long `apply` waits for the components to report.  One that does
      # not load extensions never reports.
      REPORT_SECONDS = 5

      def initialize(stdout:, client_factory:, sleeper: ->(seconds) { sleep(seconds) })
        @stdout = stdout
        @client_factory = client_factory
        @sleeper = sleeper
      end

      def run(arguments)
        command, *rest = arguments
        case command
        when "apply" then each_file(rest) { |name, source| apply(name, source) }
        when "check" then each_file(rest) { |name, source| check(name, source) }
        when "list" then list
        when "delete" then delete(rest)
        else raise Client::UsageError, USAGE
        end
      end

      private

      def client
        @client ||= @client_factory.call
      end

      # team_rules.rb is the extension "team-rules".
      def each_file(paths)
        raise Client::UsageError, "name at least one .rb file" if paths.empty?

        paths.each { |path| yield(File.basename(path, ".rb").tr("_", "-").downcase, File.read(path)) }
      rescue SystemCallError => error
        raise Client::UsageError, error.message
      end

      # A source that does not load is refused here, before it replaces a
      # version that works.
      def check(name, source)
        compiled = Definition.compile(name, source)
        @stdout.puts("#{name}: #{compiled.provides.empty? ? "declares nothing" : compiled.provides.join("  ")}")
        compiled
      rescue CompileError => error
        raise Client::UsageError, "#{name}: #{error.message}"
      end

      def apply(name, source)
        check(name, source)
        applied = client.apply(Extension.manifest(name, source), path: "#{PATH}/#{name}", field_manager: "rubectl", force: true)
        report(name, applied.dig("metadata", "generation"))
      end

      def report(name, generation)
        components = {}
        (REPORT_SECONDS * 4).times do
          components = JSON.parse(client.raw("GET", "#{PATH}/#{name}").body).dig("status", "components") || {}
          break if COMPONENTS.all? { |component| components.dig(component, "observedGeneration") == generation }

          @sleeper.call(0.25)
        end
        COMPONENTS.each do |component|
          status = components[component]
          state = if status.nil? || status["observedGeneration"] != generation
                    "no report (extensions not enabled there?)"
                  else
                    status["loaded"] ? "loaded" : "FAILED: #{status["message"]}"
                  end
          @stdout.puts(format("  %-11<component>s %<state>s", component: component, state: state))
        end
      end

      def list
        items = JSON.parse(client.raw("GET", PATH).body).fetch("items", [])
        @stdout.puts("NAME                     SCHEDULER  ADMISSION  CONTROLLER  FAILURES  PROVIDES")
        items.each do |item|
          components = item.dig("status", "components") || {}
          states = COMPONENTS.map { |component| {nil => "-", true => "loaded", false => "failed"}.fetch(components.dig(component, "loaded")) }
          failures = components.each_value.sum { |status| status["failures"].to_i }
          provides = components.each_value.flat_map { |status| status["provides"] || [] }.uniq
          @stdout.puts(format("%-24s %-10s %-10s %-11s %-9d %s", item.dig("metadata", "name"), *states, failures, provides.join(" ")))
        end
      end

      def delete(names)
        raise Client::UsageError, "name at least one extension" if names.empty?

        names.each do |name|
          client.raw("DELETE", "#{PATH}/#{name}")
          @stdout.puts("extension #{name.inspect} deleted")
        end
      end
    end
  end
end
