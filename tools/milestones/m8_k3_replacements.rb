# frozen_string_literal: true

require_relative "../conformance/k3_csi_restart_contracts"
require_relative "../conformance/archived_artifact"
require_relative "../conformance/k3_internal_contract_index"
require_relative "../conformance/k3_junit"
require_relative "../conformance/k3_local_volume_contract_index"

class M8K3Replacements
  Internal = Conformance::K3InternalContractIndex
  LocalVolume = Conformance::K3LocalVolumeContractIndex
  CSI = Conformance::K3CSIContractIndex
  Invalid = Conformance::ArchivedArtifact::Invalid
  REPORT = %r{/k3/(csi-replacements/(?:[\w-]+/)?(?:ginkgo\.json(?:\.gz)?|node-observations\.json))\z}
  JUNIT = %r{/k3/(csi-replacements/(?:[\w-]+/)?junit_\d+\.xml\.gz)\z}
  SHA256 = /\A[0-9a-f]{64}\z/
  RUNNERS = {Internal => "internal", LocalVolume => "local-volume", CSI => "csi"}.freeze

  def initialize(entries, read, artifact)
    @entries = entries.group_by { |entry| entry.fetch("replacement_test") }
    @read = read
    @artifact = artifact
  end

  def verify!
    RUNNERS.each do |index, name|
      entries = @entries.fetch(index::RUNNER, [])
      verify_runner!(index, entries, name) unless entries.empty?
    end
  end

  private

  def verify_runner!(index, entries, name)
    execution = @read.call("#{name}-replacements-command.json")
    keys = entries.map { |entry| entry.fetch("replacement_case") }.uniq
    cases = index::CASES.values.uniq.select { |key| keys.include?(key) }
    executable, runner, *arguments = execution.fetch("command")
    unless execution["exit_status"] == 0 && execution["timed_out"] == false && executable.is_a?(String) &&
           File.basename(executable).start_with?("ruby") && runner.is_a?(String) && runner.end_with?("/#{index::RUNNER}") &&
           arguments == cases
      raise Invalid, "K3 #{name} replacement command did not pass for the exact linked cases"
    end

    output = JSON.parse(execution.fetch("stdout"))
    raise Invalid, "K3 #{name} replacement runner produced no original report" unless output.is_a?(Hash)

    results = output.fetch("results")
    raise Invalid, "K3 #{name} replacement runner produced no original result rows" unless results.is_a?(Array) && results.all?(Hash)

    rows = results.group_by { |result| result.fetch("id") }
    raise Invalid, "K3 #{name} replacement output does not match the linked ledger IDs" unless rows.keys.sort == entries.map { |entry| entry.fetch("id") }.sort

    observations = csi_reports(output) if index == CSI
    entries.each do |entry|
      id, key = entry.values_at("id", "replacement_case")
      matches = rows.fetch(id)
      row = matches.first
      unless matches.one? && row["passed"] == true && row["replacement_case"] == key &&
             (index == Internal || row["file"] == index::FILES.fetch(key)) && observed?(row, key, observations)
        raise Invalid, "K3 replacement #{key} has no passing original for #{id}"
      end
    end
  end

  def observed?(row, key, csi)
    return row["observations"].is_a?(Hash) && !row["observations"].empty? unless csi

    specs, nodes = csi
    suffix = CSI.patterned_suffix(key)
    if Conformance::K3CSIRestartContracts::CASES.key?(key)
      observations = nodes.select { |report| report.key?(key) }.map { |report| report.fetch(key) }
      row["replacement_name"] == suffix && observations.one? && observations.first.is_a?(Hash) && observations.first["state"] == "passed"
    else
      name = "#{CSI.external_for(key)} #{suffix}"
      row["replacement_name"] == name && specs.fetch([name, CSI::FILES.fetch(key)], []) == ["passed"]
    end && row["states"] == ["passed"]
  end

  def csi_reports(output)
    reports = output.key?("reports") ? output.fetch("reports") : [output.fetch("report")]
    unless output["passed"] == true && reports.is_a?(Array) && !reports.empty? && reports.uniq == reports
      raise Invalid, "K3 CSI replacements have no complete original reports"
    end

    paths = reports.map do |report|
      relative = report.is_a?(String) && report[REPORT, 1]
      raise Invalid, "K3 CSI report is outside the original campaign" unless relative

      relative
    end
    raise Invalid, "K3 CSI replacements recorded duplicate original reports" unless paths.map { |path| path.delete_suffix(".gz") }.uniq.length == paths.length

    metadata = verify_csi_artifacts!(output.fetch("report_artifacts", []), paths)
    specs = Hash.new { |hash, key| hash[key] = [] }
    nodes = []
    paths.each do |relative|
      document = JSON.parse(read_csi_report(relative, metadata[relative]))
      if File.basename(relative).delete_suffix(".gz") == "ginkgo.json"
        add_csi_suite!(document, specs)
      else
        raise Invalid, "K3 CSI original node observations must be a JSON object" unless document.is_a?(Hash)

        nodes << document
      end
    end
    [specs, nodes]
  end

  def verify_csi_artifacts!(artifacts, paths)
    raise Invalid, "K3 CSI report artifacts must be an array" unless artifacts.is_a?(Array)

    ginkgo = paths.reject { |path| path.end_with?("/node-observations.json") }
    directories = ginkgo.map { |path| File.dirname(path) }
    artifacts.each_with_object({}) do |artifact, metadata|
      path = artifact.is_a?(Hash) && artifact["path"]
      raise Invalid, "K3 CSI report artifact has no identity" unless path.is_a?(String) && SHA256.match?(artifact["sha256"].to_s)

      relative = path[REPORT, 1]
      if ginkgo.include?(relative) && !metadata.key?(relative)
        metadata[relative] = artifact
        next
      end

      relative = path[JUNIT, 1]
      unless relative && directories.delete(File.dirname(relative)) &&
             Conformance::K3JUnit.complete_xml?(read_csi_report(relative, artifact))
        raise Invalid, "K3 CSI replacement has unexpected or invalid JUnit artifact"
      end
    end
  end

  def read_csi_report(relative, metadata)
    path = @artifact.call(relative, unique_format: true)
    raise Invalid, "K3 CSI stored report SHA-256 differs: #{relative}" if metadata && Digest::SHA256.file(path).hexdigest != metadata.fetch("sha256")
    return File.binread(path) unless relative.end_with?(".gz")

    digest, size = metadata&.values_at("uncompressed_sha256", "uncompressed_bytes")
    unless SHA256.match?(digest.to_s) && size.is_a?(Integer) && size.positive?
      raise Invalid, "K3 CSI archived report has no original byte identity: #{relative}"
    end

    bytes = Conformance::ReportArchive.read(path, sha256: digest, alternate: false)
    raise Invalid, "K3 CSI original report size differs: #{relative}" unless bytes.bytesize == size

    bytes
  end

  def add_csi_suite!(document, specs)
    unless document.is_a?(Array) && document.one? && document.first.is_a?(Hash) && document.first["SuiteSucceeded"] == true
      raise Invalid, "K3 CSI original Ginkgo replacement suite did not pass"
    end

    reports = document.first.fetch("SpecReports")
    raise Invalid, "K3 CSI original Ginkgo suite did not record its spec reports" unless reports.is_a?(Array) && reports.all?(Hash)

    reports.each do |spec|
      next unless spec["LeafNodeType"] == "It"

      name = (spec.fetch("ContainerHierarchyTexts") + [spec.fetch("LeafNodeText")]).reject(&:empty?).join(" ")
      file = spec.dig("LeafNodeLocation", "FileName").to_s.sub(%r{\A(?:.*/kubernetes-v1\.36\.2/|k8s\.io/kubernetes/)}, "")
      specs[[name, file]] << spec["State"] unless spec["State"] == "skipped"
    end
  end
end
