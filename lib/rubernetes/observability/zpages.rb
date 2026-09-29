# frozen_string_literal: true

require "cgi"
require "json"
require "yaml"

module Rubernetes
  module Observability
    # /statusz and /flagz (ComponentStatusz, ComponentFlagz: Beta, on) as
    # k8s.io/apiserver/pkg/server/{statusz,flagz} serve them for every
    # component: human-readable text by default (a random delimiter, so no one
    # parses it), or the config.k8s.io Statusz/Flagz objects when the Accept
    # header asks for them by kind (application/json;g=config.k8s.io;
    # v=v1beta1;as=Statusz, or yaml); v1alpha1 is served with a deprecation
    # Warning.  Anything else is 406.
    module ZPages
      GROUP = "config.k8s.io"
      # The Kubernetes release every component implements (binary and
      # emulation version).
      KUBERNETES_VERSION = "1.36.2"
      VERSIONS = %w[v1beta1 v1alpha1].freeze
      DEPRECATED_VERSIONS = %w[v1alpha1].freeze
      DELIMITERS = [":", ": ", "=", " "].freeze
      NON_DEBUGGING_ENDPOINTS = %w[/apis /api /openid /openapi /.well-known].freeze
      ACCEPTED = %w[application/json application/yaml text/plain].freeze
      DEPRECATION_WARNING = %(299 - "This version of the %s endpoint is deprecated. Please use a newer version.")

      module_function

      def header(component, page)
        "\n#{component} #{page}\nWarning: This endpoint is not meant to be machine parseable, has no formatting compatibility " \
          "guarantees and is for debugging purposes only.\n"
      end

      # [status, headers, body] for /statusz.
      def statusz(component:, start_time:, binary_version:, emulation_version: nil, runtime_version: RUBY_DESCRIPTION,
                  paths: [], accept: nil, now: Time.now, random: Random)
        listed = aggregate_paths(paths)
        uptime = [(now - start_time).to_i, 0].max
        respond(accept, "Statusz") do |format, version|
          if format == :text
            delimiter = CGI.escapeHTML(DELIMITERS.sample(random: random))
            emulation = emulation_version.to_s.empty? ? "" : "Emulation version#{delimiter} #{CGI.escapeHTML(emulation_version.to_s)}"
            listed_paths = listed.empty? ? "" : "Paths#{delimiter} #{CGI.escapeHTML(listed.join(" "))}"
            header(component, "statusz") +
              "\nStarted#{delimiter} #{CGI.escapeHTML(start_time.strftime("%a %b %e %H:%M:%S %Z %Y"))}" \
              "\nUp#{delimiter} #{CGI.escapeHTML(format_uptime(uptime))}" \
              "\nGo version#{delimiter} #{CGI.escapeHTML(runtime_version.to_s)}" \
              "\nBinary version#{delimiter} #{CGI.escapeHTML(binary_version.to_s)}" \
              "\n#{emulation}\n#{listed_paths}\n"
          else
            object = {"kind" => "Statusz", "apiVersion" => "#{GROUP}/#{version}", "metadata" => {"name" => component},
                      "startTime" => start_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ"), "uptimeSeconds" => uptime,
                      "goVersion" => runtime_version.to_s, "binaryVersion" => binary_version.to_s}
            object["emulationVersion"] = emulation_version.to_s unless emulation_version.to_s.empty?
            object["paths"] = listed.empty? ? nil : listed
            object
          end
        end
      end

      # [status, headers, body] for /flagz; +flags+ maps a flag name to its
      # value (strings).
      def flagz(component:, flags:, accept: nil, random: Random)
        respond(accept, "Flagz") do |format, version|
          if format == :text
            separator = DELIMITERS.sample(random: random)
            header(component, "flagz") + flags.sort.map { |name, value| "#{name}#{separator}#{value}\n" }.join
          else
            object = {"kind" => "Flagz", "apiVersion" => "#{GROUP}/#{version}", "metadata" => {"name" => component}}
            object["flags"] = flags.to_h { |name, value| [name.to_s, value.to_s] } unless flags.empty?
            object
          end
        end
      end

      # statusz aggregatePaths: the first path segment of every listed path,
      # without the API and discovery trees, sorted.
      def aggregate_paths(paths)
        Array(paths).filter_map do |path|
          segment = path.to_s.split("/")[1]
          next if segment.nil? || segment.empty?

          folder = "/#{segment}"
          folder unless NON_DEBUGGING_ENDPOINTS.include?(folder)
        end.uniq.sort
      end

      # The process start (/proc/self/stat starttime + btime), as the
      # statusz registry's GetProcessStart.
      def process_start_time
        stat = File.read("/proc/self/stat")
        ticks = Integer(stat[stat.rindex(")") + 2..].split.fetch(19))
        boot = File.foreach("/proc/stat").find { |line| line.start_with?("btime ") }
        Time.at(Integer(boot.split[1]) + (ticks / 100))
      rescue SystemCallError, ArgumentError, IndexError, NoMethodError
        Time.now
      end

      def format_uptime(seconds) = format("%d hr %02d min %02d sec", seconds / 3600, (seconds / 60) % 60, seconds % 60)

      # A config-file component's "flags": its command line, then its loaded
      # configuration flattened to dotted keys (values that look secret are
      # not shown).
      def flags_from(arguments: [], config: {})
        flags = {}
        Array(arguments).each do |argument|
          next unless argument.start_with?("--")

          name, value = argument.delete_prefix("--").split("=", 2)
          flags[name] = value.nil? ? "true" : value
        end
        flatten(config, "", flags)
        flags
      end

      SECRET_KEY = /(password|secret|token|private_key)\z/i.freeze

      def flatten(value, prefix, into)
        case value
        when Hash
          value.each { |key, nested| flatten(nested, prefix.empty? ? key.to_s : "#{prefix}.#{key}", into) }
        when Array
          into[prefix] = value.all? { |item| !item.is_a?(Hash) && !item.is_a?(Array) } ? value.join(",") : JSON.generate(value)
        else
          into[prefix] = prefix.match?(SECRET_KEY) ? "<redacted>" : value.to_s
        end
      end

      def respond(accept, kind)
        if accept.to_s.strip.empty?
          return [200, {"content-type" => "text/plain; charset=utf-8"}, yield(:text, nil)]
        end

        choice = negotiate(accept, kind)
        if choice.nil?
          body = {"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Failure",
                  "message" => "only the following media types are accepted: #{ACCEPTED.join(", ")}", "reason" => "NotAcceptable", "code" => 406}
          return [406, {"content-type" => "application/json"}, JSON.generate(body)]
        end

        media, version = choice
        return [200, {"content-type" => "text/plain; charset=utf-8"}, yield(:text, nil)] if media == "text/plain"

        headers = {"content-type" => media}
        headers["warning"] = format(DEPRECATION_WARNING, kind.downcase) if DEPRECATED_VERSIONS.include?(version)
        object = yield(:structured, version)
        [200, headers, media == "application/yaml" ? YAML.dump(object.compact).delete_prefix("---\n") : JSON.generate(object)]
      end

      # The first acceptable Accept entry: text/plain (no parameters), or
      # JSON/YAML naming this kind in config.k8s.io at a served version.
      def negotiate(accept, kind)
        accept.to_s.split(",").each do |entry|
          media, *parameters = entry.split(";").map(&:strip)
          options = parameters.to_h { |parameter| parameter.split("=", 2).map(&:strip) }
          media = media.to_s.downcase
          # A wildcard without a kind falls through to the only type that
          # needs none.
          media = "text/plain" if media == "text/*" || (media == "*/*" && !options.key?("as"))
          if media == "text/plain"
            return ["text/plain", nil] unless options.key?("as")

            next
          end
          if %w[application/json application/yaml].include?(media) || media == "*/*"
            next unless options["as"] == kind && options["g"] == GROUP && VERSIONS.include?(options["v"])

            return [media == "*/*" ? "application/json" : media, options["v"]]
          end
        end
        nil
      end
    end
  end
end
