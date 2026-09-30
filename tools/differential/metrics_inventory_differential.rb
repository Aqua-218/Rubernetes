#!/usr/bin/env ruby
# frozen_string_literal: true

# Rubernetes' metrics against upstream's v1.36.2 inventory
# (schema/kubernetes/v1.36.2-defaults/metrics.json, imported from
# test/instrumentation/documentation/documentation-list.yaml by
# tools/schema/import_kubernetes_metrics.rb).
#
# Static mode (default): for each component, every upstream metric is
#   wired        -- lib/ writes it (a string literal outside a register call,
#                   or one of the DYNAMIC names built by interpolation),
#   hidden       -- deprecated long enough that component-base hides it
#                   (Metrics.hidden?): not served, upstream or here,
#   upstream-unused -- declared upstream but recorded nowhere in v1.36.2,
#   unimplemented -- Metrics::UNIMPLEMENTED: the feature it measures does not
#                   exist in Rubernetes; declared with the reason in its HELP
#                   (and logged as metrics.unimplemented), never written,
#   unwired      -- neither: registered from the inventory and never written.
#
# Scrape mode (--scrape component[:endpoint]=path|url, repeatable; endpoint
# defaults to /metrics): each exposition is
# parsed by Go's expfmt text parser (test/conformance/kubernetes/
# metrics_expfmt_oracle, compiled into k8s.io/component-base/metrics/testutil
# through a go test overlay), and every family is compared with the
# inventory: known to upstream for that component, same type, same help
# ([STABILITY] annotated), same label names, same bucket bounds as Go
# formats them.  Upstream metrics that should always show (no labels) but
# are absent are listed too.
#
#   ruby tools/differential/metrics_inventory_differential.rb [--component kube-apiserver] [--unwired-only]
#   ruby tools/differential/metrics_inventory_differential.rb --scrape kube-apiserver=/tmp/apiserver.txt \
#        [--scrape kube-controller-manager=https://127.0.0.1:20257/metrics --insecure --token T]

require "json"
require "net/http"
require "open3"
require "openssl"
require "tmpdir"
require "uri"
require_relative "../../lib/rubernetes/observability/metrics"

module MetricsInventoryDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/metrics_expfmt_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  PACKAGE = "k8s.io/component-base/metrics/testutil"
  METRICS = Rubernetes::Observability::Metrics
  COMPONENTS = %w[kube-apiserver kube-controller-manager kube-scheduler kubelet kube-proxy].freeze

  # Names lib/ builds by interpolation, with the file and the fragment that
  # builds them (checked, so a rename shows up as unwired).
  DYNAMIC = {
    "kube_apiserver_clusterip_allocator_allocation_total" => ["api/service_allocator.rb", "kube_apiserver_clusterip_allocator_allocation"],
    "kube_apiserver_clusterip_allocator_allocation_errors_total" => ["api/service_allocator.rb", "kube_apiserver_clusterip_allocator_allocation"],
    "kube_apiserver_nodeport_allocator_allocation_total" => ["api/service_allocator.rb", "kube_apiserver_nodeport_allocator_allocation"],
    "kube_apiserver_nodeport_allocator_allocation_errors_total" => ["api/service_allocator.rb", "kube_apiserver_nodeport_allocator_allocation"],
    "authentication_duration_seconds" => ["security/pipeline.rb", "\#{kind}_duration_seconds"],
    "authorization_duration_seconds" => ["security/pipeline.rb", "\#{kind}_duration_seconds"],
    "storage_count_attachable_volumes_in_use" => ["bootstrap/control_plane_services.rb", "storage_count_attachable_volumes_in_use"],
    "attachdetach_controller_total_volumes" => ["bootstrap/control_plane_services.rb", "attachdetach_controller_total_volumes"]
  }.freeze

  # Declared and registered upstream but never recorded anywhere in
  # v1.36.2 (so upstream never shows a series either).
  UPSTREAM_UNUSED = {
    "aggregator_openapi_v2_regeneration_count" => "kube-aggregator/pkg/controllers/openapi/aggregator/metrics.go: no caller",
    "aggregator_openapi_v2_regeneration_duration" => "kube-aggregator/pkg/controllers/openapi/aggregator/metrics.go: no caller"
  }.freeze

  # Upstream types as the text format spells them.
  TEXT_TYPES = {"Counter" => "COUNTER", "Gauge" => "GAUGE", "Histogram" => "HISTOGRAM", "TimingRatioHistogram" => "HISTOGRAM",
                "Summary" => "SUMMARY"}.freeze

  module_function

  def lib_sources
    @lib_sources ||= Dir[File.join(ROOT, "lib/**/*.rb")].to_h { |path| [path.delete_prefix("#{ROOT}/lib/rubernetes/"), File.read(path)] }
  end

  # Every line of lib/ that names +name+ in quotes and is not a register or
  # unregister call or the UNIMPLEMENTED table.
  def written_literally?(name)
    needle = "\"#{name}\""
    lib_sources.any? do |_path, text|
      next false unless text.include?(needle)

      text.each_line.any? { |line| line.include?(needle) && !line.match?(/\bregister\(|unregister\(|UNIMPLEMENTED_ENTRY/) }
    end
  end

  def dynamic?(name)
    file, fragment = DYNAMIC[name]
    file && lib_sources[file]&.include?(fragment)
  end

  def classify(component)
    unimplemented = METRICS::UNIMPLEMENTED.fetch(component, {})
    METRICS.upstream.select { |_name, entry| entry["components"].include?(component) }.map do |name, entry|
      state = if METRICS.hidden?(entry) then "hidden"
              elsif UPSTREAM_UNUSED.key?(name) then "upstream-unused"
              elsif unimplemented.key?(name) then "unimplemented"
              elsif written_literally?(name) || dynamic?(name) then "wired"
              else "unwired"
              end
      {"name" => name, "type" => entry["type"], "labels" => entry["labels"], "endpoints" => entry.dig("endpoints", component),
       "state" => state, "reason" => unimplemented[name] || UPSTREAM_UNUSED[name]}
    end
  end

  def static_report(components, unwired_only: false)
    components.each do |component|
      rows = classify(component)
      counts = rows.group_by { |row| row["state"] }.transform_values(&:length)
      puts "== #{component}: #{rows.length} upstream; wired #{counts["wired"].to_i}, hidden #{counts["hidden"].to_i}, " \
           "upstream-unused #{counts["upstream-unused"].to_i}, unimplemented #{counts["unimplemented"].to_i}, unwired #{counts["unwired"].to_i}"
      rows.sort_by { |row| [row["state"], row["name"]] }.each do |row|
        next if row["state"] == "wired" && unwired_only
        next if %w[unimplemented hidden upstream-unused].include?(row["state"]) && unwired_only

        detail = row["reason"] ? " -- #{row["reason"]}" : ""
        puts format("  %-13s %-s %s %s%s", row["state"], row["name"], row["type"], row["labels"].inspect, detail)
      end
    end
  end

  # The exposition parsed by Go's expfmt.
  def run_oracle(inputs)
    Dir.mktmpdir("metrics-expfmt-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate(inputs))
      package = File.join(File.realpath(SOURCE), "staging/src", PACKAGE)
      File.write(overlay, JSON.generate("Replace" => {File.join(package, "zz_rubernetes_oracle_test.go") => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, PACKAGE, "-run", "TestRubernetesExpfmtOracle", "-count=1",
                                       chdir: File.realpath(SOURCE))
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output))
    end
  end

  def fetch(location, insecure:, token:)
    return File.read(location) unless location.match?(%r{\Ahttps?://})

    uri = URI(location)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if insecure
    request = Net::HTTP::Get.new(uri)
    request["Authorization"] = "Bearer #{token}" if token
    response = http.request(request)
    raise "#{location}: HTTP #{response.code}" unless response.code == "200"

    response.body
  end

  # A family's differences from the inventory ([] when it matches).
  def family_problems(component, family)
    name = family["name"]
    entry = METRICS.upstream[name]
    return ["not in the upstream inventory"] unless entry
    return ["upstream does not serve it from #{component}"] unless entry["components"].include?(component)

    problems = []
    want_type = TEXT_TYPES[entry["type"]]
    problems << "type #{family["type"]} != upstream #{entry["type"]}" if want_type && family["type"] != want_type
    want_help = METRICS.annotated_help(entry)
    problems << "help #{family["help"].inspect} != #{want_help.inspect}" if family["help"] != want_help
    want_labels = (Array(entry["labels"]) + Array(entry["constLabels"]&.keys)).sort
    family["labels"].each do |labels|
      problems << "labels #{labels.inspect} != upstream #{want_labels.inspect}" unless labels == want_labels
    end
    if entry["buckets"] && family["buckets"]
      want = entry["buckets"].map { |bound| METRICS.go_float(bound.to_f) } + ["+Inf"]
      problems << "buckets #{family["buckets"].inspect} != upstream #{want.inspect}" unless family["buckets"] == want
    end
    problems
  end

  # Families this process adds that are not component metrics upstream
  # tracks in its inventory (client_golang's own collectors).
  COLLECTOR_PREFIXES = %w[process_ go_].freeze

  # +scrapes+: [[component, endpoint, location]].
  def scrape_report(scrapes, insecure:, token:)
    inputs = scrapes.map { |component, _endpoint, location| {"component" => component, "body" => fetch(location, insecure: insecure, token: token)} }
    total_failures = 0
    run_oracle(inputs).zip(scrapes).each do |result, (component, endpoint, _location)|
      puts "== #{component} #{endpoint}: #{result["families"].length} families parsed by expfmt"
      failures = 0
      if result["error"]
        failures += 1
        puts "  PARSE ERROR #{result["error"]}"
      end
      checked = 0
      mismatched = 0
      result["families"].each do |family|
        next if COLLECTOR_PREFIXES.any? { |prefix| family["name"].start_with?(prefix) } && !METRICS.upstream.key?(family["name"])

        checked += 1
        problems = family_problems(component, family)
        next if problems.empty?

        mismatched += 1
        problems.each { |problem| puts "  MISMATCH #{family["name"]}: #{problem}" }
      end
      served = result["families"].to_h { |family| [family["name"], true] }
      unimplemented = METRICS::UNIMPLEMENTED.fetch(component, {})
      absent = 0
      METRICS.upstream.each do |name, entry|
        next unless entry["components"].include?(component) && Array(entry.dig("endpoints", component)).include?(endpoint)
        next unless entry["labels"].empty? && TEXT_TYPES.key?(entry["type"]) && entry["type"] != "Summary"
        next if served[name] || unimplemented.key?(name) || METRICS.hidden?(entry)

        absent += 1
        puts "  ABSENT #{name} (#{entry["type"]}, no labels: upstream always shows it)"
      end
      result["lint"].each { |problem| puts "  lint #{problem}" } if ENV["METRICS_LINT"]
      puts "  #{checked - mismatched}/#{checked} families match the inventory; #{absent} always-present families absent"
      total_failures += failures + mismatched + absent
    end
    total_failures.zero? ? 0 : 1
  end

  def main(argv)
    scrapes = []
    argv.each_with_index do |arg, index|
      next unless arg == "--scrape"

      target, location = argv[index + 1].split("=", 2)
      component, endpoint = target.split(":", 2)
      scrapes << [component, endpoint || "/metrics", location]
    end
    if scrapes.any?
      token = argv.include?("--token") ? argv[argv.index("--token") + 1] : nil
      return scrape_report(scrapes, insecure: argv.include?("--insecure"), token: token)
    end

    components = argv.include?("--component") ? [argv[argv.index("--component") + 1]] : COMPONENTS
    static_report(components, unwired_only: argv.include?("--unwired-only"))
    0
  end
end

exit MetricsInventoryDifferential.main(ARGV) if $PROGRAM_NAME == __FILE__
