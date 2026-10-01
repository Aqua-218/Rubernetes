# frozen_string_literal: true

require "json"
require "fileutils"
require "minitest/autorun"
require "tmpdir"
require_relative "../../tools/milestones/m2_gate"
require_relative "../../tools/milestones/m4_gate"
require_relative "../../tools/milestones/m3_evidence_support"

class M4GateTest < Minitest::Test
  def test_source_exclusions_match_the_m0_to_m2_rule
    excluded = lambda do |path|
      M4Gate::SOURCE_EXCLUDED_ROOTS.include?(path.split("/", 2).first) ||
        M4Gate::SOURCE_EXCLUDED_PATTERNS.any? { |pattern| pattern.match?(path) }
    end

    assert(excluded.call("a11-generated.u1BHO1/generated.rb"))
    assert(excluded.call("artifacts/milestones/M0/x.json"))
    refute(excluded.call("a11-generated.bad/source.rb"))
    refute(excluded.call("a11-generated.u1BHO1x"))
    refute(excluded.call("nested/a11-generated.u1BHO1/source.rb"))
    assert_equal(M4Gate::SOURCE_EXCLUDED_PATTERNS, M2Gate::SOURCE_EXCLUDED_PATTERNS)
    assert_equal(M4Gate::SOURCE_EXCLUDED_ROOTS, M2Gate::SOURCE_EXCLUDED_ROOTS)
  end

  def test_missing_manifest_fails_closed
    result = M4Gate.evaluate(File.join(Dir.tmpdir, "rubernetes-m4-missing-#{Process.pid}.json"))

    refute result.fetch("passed")
    assert_operator result.fetch("error_count"), :>, 0
  end

  def test_m4_requires_the_complete_m3_chain
    Dir.mktmpdir("rubernetes-m4-gate") do |directory|
      path = File.join(directory, "manifest.json")
      File.write(path, JSON.generate("schema_version" => 3, "milestone" => "M4", "status" => "INCOMPLETE",
                                     "input_sha256" => "0" * 64, "input_file_count" => 1,
                                     "input_stable" => true, "host" => {"architecture" => "x86_64", "kernel" => "test", "ruby" => RUBY_DESCRIPTION},
                                     "started_at" => Time.now.utc.iso8601, "finished_at" => Time.now.utc.iso8601,
                                     "input_capture" => {"stable" => true, "start" => {"sha256" => "0" * 64, "file_count" => 1},
                                                         "finish" => {"sha256" => "0" * 64, "file_count" => 1}},
                                     "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
                                     "commands" => [{"name" => "fixture", "command" => ["fixture"], "started_at" => Time.now.utc.iso8601, "finished_at" => Time.now.utc.iso8601, "exit_status" => 0}],
                                     "artifacts" => [], "subjects" => [], "result_counts" => {"commands" => 1, "command_failures" => 0, "artifacts" => 0, "subjects" => 0, "reports" => 5, "source_files" => 1}))

      result = M4Gate.evaluate(path)

      refute result.fetch("passed")
      assert(result.fetch("errors").any? { |error| error.include?("M3") || error.include?("source inventory") })
    end
  end

  def test_kernel_below_612_is_rejected_even_with_a_complete_shape
    now = Time.now.utc.iso8601
    errors = []
    manifest = {"schema_version" => 3, "milestone" => "M4", "status" => "INCOMPLETE",
                "input_sha256" => "0" * 64, "input_file_count" => 1, "input_stable" => true,
                "host" => {"architecture" => "x86_64", "kernel" => "5.15.0-test", "ruby" => RUBY_DESCRIPTION},
                "started_at" => now, "finished_at" => now,
                "input_capture" => {"stable" => true, "start" => {"sha256" => "0" * 64, "file_count" => 1},
                                    "finish" => {"sha256" => "0" * 64, "file_count" => 1}},
                "git_metadata_capture" => {"stable" => true, "start_paths" => [], "finish_paths" => [], "count" => 0},
                "commands" => [{"name" => "fixture", "command" => ["fixture"], "started_at" => now, "finished_at" => now, "exit_status" => 0}],
                "artifacts" => [], "subjects" => [], "result_counts" => {"commands" => 1, "command_failures" => 0,
                                                                         "artifacts" => 0, "subjects" => 0, "reports" => 5, "source_files" => 1}}

    M4Gate.send(:validate_manifest_shape, manifest, errors)

    assert(errors.any? { |error| error.include?("kernel") && error.include?("6.12") })
  end

  def test_kernel_requirement_accepts_only_an_explicit_host_bound_waiver
    host = {"architecture" => "x86_64", "kernel" => "6.8.0-138-generic", "ruby" => RUBY_DESCRIPTION}
    errors = []
    M4Gate.send(:validate_kernel_requirement, {"waivers" => []}, host, errors)

    assert(errors.any? { |error| error.include?("Linux kernel >= 6.12") && error.include?("waiver") })

    waiver = {"requirement" => "linux>=6.12", "scope" => "m4-kernel-release", "reason" => "host cannot be rebooted",
              "host_kernel" => "6.8.0-138-generic", "waived_at" => Time.now.utc.iso8601}
    errors = []
    M4Gate.send(:validate_kernel_requirement, {"waivers" => [waiver]}, host, errors)

    assert_empty errors
    assert_equal [waiver], M4Gate.send(:result, []).fetch("waivers")

    errors = []
    M4Gate.send(:validate_kernel_requirement, {"waivers" => [waiver.merge("host_kernel" => "6.5.0")]}, host, errors)

    assert(errors.any? { |error| error.include?("waiver") })

    errors = []
    M4Gate.send(:validate_kernel_requirement, {"waivers" => [waiver]}, host.merge("kernel" => "6.12.0"), errors)

    assert_empty errors
    assert_empty M4Gate.send(:result, []).fetch("waivers")
  end

  def test_network_observation_rejects_missing_real_packet_trace
    now = Time.now.utc.iso8601
    observation = {"executed" => true, "runner_sha256" => "1" * 64,
                   "runner" => {"runner_sha256" => "1" * 64, "command" => ["network-runner"],
                                "process_id" => 10, "started_at" => now, "finished_at" => now},
                   "netns" => {"path" => "/proc/10/ns/net", "pid" => 10, "inode" => 11},
                   "kernel_objects" => [{"kind" => "netns", "id" => "11", "observed" => true}],
                   "packet_trace" => {"format" => "text", "sha256" => "2" * 64, "packet_count" => 0, "command" => ["tcpdump"]}}
    errors = []

    M4Gate.send(:validate_network_observation, observation, errors)

    assert(errors.any? { |error| error.include?("packet trace") })
  end

  def test_proxy_readback_rejects_in_process_rule_digest_without_kernel_ids
    now = Time.now.utc.iso8601
    readback = {"executed" => true, "runner_sha256" => "3" * 64,
                "runner" => {"runner_sha256" => "3" * 64, "command" => ["proxy-runner"],
                             "process_id" => 12, "started_at" => now, "finished_at" => now},
                "ebpf" => {"verified" => true, "readback" => true, "program_id" => 0, "map_id" => 0,
                           "verifier_log_sha256" => "4" * 64, "rules" => [{"id" => "r"}]},
                "nftables" => {"readback" => true, "family" => "inet", "table" => "rubernetes",
                               "rules" => [{"id" => "r"}], "ruleset_sha256" => "5" * 64},
                "parity" => {"expected_observable" => {}, "actual_observable" => {},
                             "expected_sha256" => M4Gate.canonical_document_digest({}),
                             "actual_sha256" => M4Gate.canonical_document_digest({})}}
    errors = []

    M4Gate.send(:validate_proxy_readback, readback, errors)

    assert(errors.any? { |error| error.include?("eBPF") })
  end

  def test_policy_oracle_rejects_boolean_observables
    digest = "6" * 64
    errors = []
    comparison = {"id" => "default_deny", "passed" => true, "expected_observable" => true,
                  "actual_observable" => true, "expected_sha256" => digest, "actual_sha256" => digest}

    M4Gate.send(:validate_observable_comparison, comparison, errors, "policy mutation")

    assert(errors.any? { |error| error.include?("structured") || error.include?("observable") })
  end

  def test_external_kernel_observation_rejects_a_local_probe_digest
    now = Time.now.utc.iso8601
    local_digest = "7" * 64
    observation = {"executed" => true, "runner_sha256" => local_digest,
                   "runner" => {"runner_sha256" => local_digest, "command" => ["network-runner"],
                                "process_id" => 20, "started_at" => now, "finished_at" => now},
                   "netns" => {"path" => "/proc/20/ns/net", "pid" => 20, "inode" => 21},
                   "kernel_objects" => [{"kind" => "netns", "id" => "21", "observed" => true}],
                   "packet_trace" => {"format" => "pcap", "sha256" => "8" * 64,
                                      "packet_count" => 1, "command" => ["tcpdump"]}}
    owner = {"adapter" => {"runner_sha256" => local_digest}}
    errors = []

    M4Gate.send(:validate_network_observation, observation, errors, owner_document: owner)

    assert(errors.any? { |error| error.include?("digest") && error.include?("local probe") })
  end

  def test_volume_observation_rejects_an_observed_flag_without_content_bound_values
    now = Time.now.utc.iso8601
    runner = {"runner_sha256" => "b" * 64, "command" => ["external-volume-runner"], "process_id" => Process.pid,
              "started_at" => now, "finished_at" => now, "mode" => "external", "self_comparison" => false,
              "implementation" => "independent-volume-runner"}
    observation = {
      "executed" => true, "runner_sha256" => runner["runner_sha256"], "runner" => runner,
      "mountinfo" => [{"line" => "mountinfo", "line_sha256" => Digest::SHA256.hexdigest("mountinfo"), "observed" => true}],
      "syscalls" => [{"name" => "mount", "return" => 0, "observed" => true}],
      "container_observation" => [{"container_id" => "container-a", "pid" => Process.pid, "observed" => true}]
    }
    errors = []

    M4Gate.send(:validate_volume_observation, {"kernel_observation" => observation}, errors)

    assert(errors.any? { |error| error.include?("expected and actual observations") })
  end

  def test_volume_observation_requires_content_digests_and_the_complete_csi_snapshot_operation_sets
    now = Time.now.utc.iso8601
    runner = {"runner_sha256" => "c" * 64, "command" => ["external-volume-runner"], "process_id" => Process.pid,
              "started_at" => now, "finished_at" => now, "mode" => "external", "self_comparison" => false,
              "implementation" => "independent-volume-runner"}
    content_record = lambda do |value|
      {"expected" => value, "actual" => Marshal.load(Marshal.dump(value)),
       "expected_sha256" => M4Gate.canonical_document_digest(value),
       "actual_sha256" => M4Gate.canonical_document_digest(value), "passed" => true}
    end
    observation = {
      "executed" => true, "runner_sha256" => runner["runner_sha256"], "runner" => runner,
      "mountinfo" => [{"line" => "mountinfo", "line_sha256" => Digest::SHA256.hexdigest("mountinfo")}.merge(content_record.call({"mount" => "m4"}))],
      "syscalls" => [{"name" => "mount", "return" => 0}.merge(content_record.call({"syscall" => "mount", "return" => 0}))],
      "container_observation" => [{"container_id" => "container-a", "pid" => Process.pid}.merge(content_record.call({"container" => "container-a", "pid" => Process.pid}))]
    }
    csi_operations = %w[
      GetPluginInfo CreateVolume DeleteVolume ControllerPublishVolume ControllerUnpublishVolume
      NodeStageVolume NodeUnstageVolume NodePublishVolume NodeUnpublishVolume NodeGetVolumeStats
    ]
    csi = {"executed" => true, "runner_sha256" => runner["runner_sha256"], "runner" => runner,
           "comparisons" => csi_operations.map do |operation|
             {"id" => operation}.merge(content_record.call({"operation" => operation, "result" => "ok"}))
           end}
    snapshot = {"executed" => true, "runner_sha256" => runner["runner_sha256"], "runner" => runner,
                "comparisons" => %w[snapshot_create snapshot_restore crash_recovery].map do |operation|
                  {"id" => operation}.merge(content_record.call({"operation" => operation, "result" => "ok"}))
                end}
    errors = []

    M4Gate.send(:validate_volume_observation, {"kernel_observation" => observation,
                                               "csi_oracle" => csi, "snapshot_recovery" => snapshot}, errors)

    assert_empty errors
    csi["comparisons"].reject! { |entry| entry["id"] == "NodeUnstageVolume" }
    errors = []
    M4Gate.send(:validate_volume_observation, {"kernel_observation" => observation,
                                               "csi_oracle" => csi, "snapshot_recovery" => snapshot}, errors)

    assert(errors.any? { |error| error.include?("NodeUnstageVolume") })
  end

  def test_volume_component_source_rejects_fabricated_production_module_labels
    errors = []

    M4Gate.send(:validate_volume_component_source,
                {"measurement_source" => "production_module",
                 "detail" => {"adapter_class" => "Rubernetes::Volume::FilesystemAdapter"}},
                errors, "volume kind")
    M4Gate.send(:validate_volume_component_source,
                {"measurement_source" => "production_module",
                 "detail" => {"execution" => "object_construction"}},
                errors, "volume kind")

    assert_equal 2, errors.length
    assert(errors.all? { |error| error.include?("volume kind") })
  end

  def test_packet_trace_rejects_an_external_tmp_path_even_when_digest_looks_valid
    packet = {"format" => "pcap", "path" => "/tmp/not-real", "artifact_path" => "/tmp/not-real",
              "materialized" => true, "bytes" => 24, "size" => 24, "sha256" => "9" * 64,
              "packet_count" => 1, "command" => ["tcpdump"]}
    errors = []

    M4Gate.send(:validate_materialized_packet_trace, packet, errors, "network kernel observation",
                evidence_directory: Dir.tmpdir, artifacts: [])

    assert(errors.any? { |error| error.include?("bundle-relative") })
    refute_empty errors
  end

  def test_network_observation_rejects_namespace_object_without_inode_identity_binding
    now = Time.now.utc.iso8601
    observation = {
      "executed" => true,
      "runner_sha256" => "a" * 64,
      "runner" => {"runner_sha256" => "a" * 64, "command" => ["external-network-runner"],
                   "process_id" => 42, "started_at" => now, "finished_at" => now},
      "netns" => {
        "path" => "/proc/42/ns/net", "pid" => 42, "runner_pid" => 42, "inode" => 4242,
        "identity" => {"path" => "/proc/42/ns/net", "pid" => 42, "inode" => 4242},
        "identity_sha256" => M4Gate.canonical_document_digest({"path" => "/proc/42/ns/net", "pid" => 42, "inode" => 4242})
      },
      "keeper" => {"pid" => 42, "runner_pid" => 42, "netns_inode" => 4242, "identity" => "keeper-42"},
      "kernel_objects" => [{"kind" => "link", "id" => "eth0", "observed" => true,
                            "netns_inode" => 9999, "netns_identity_sha256" => "b" * 64,
                            "identity" => {"ifindex" => 1}, "identity_sha256" => M4Gate.canonical_document_digest({"ifindex" => 1})}],
      "packet_trace" => {"format" => "text", "sha256" => "b" * 64, "packet_count" => 0,
                         "command" => ["tcpdump"]}
    }
    errors = []

    M4Gate.send(:validate_network_observation, observation, errors)

    assert(errors.any? { |error| error.include?("kernel object") && error.include?("namespace inode") })
  end

  def test_external_packet_capture_is_copied_as_regular_content_addressed_bytes
    Dir.mktmpdir("rubernetes-m4-capture") do |directory|
      source = File.join(directory, "external.pcap")
      bundle = File.join(directory, "bundle")
      report = File.join(directory, "report.json")
      FileUtils.mkdir_p(bundle)
      File.binwrite(source, pcap_bytes("PING"))
      File.write(report, JSON.generate(
        "kernel_observation" => {
          "packet_trace" => {"format" => "pcap", "path" => source, "packet_count" => 1}
        }
      ))

      result = M34EvidenceSupport.materialize_packet_trace!(report, bundle_directory: bundle, basename: "network")

      assert_equal 58, result.fetch("bytes")
      assert_equal result.fetch("sha256"), Digest::SHA256.file(File.join(bundle, "network.pcap")).hexdigest
      document = JSON.parse(File.read(report))

      assert_equal "network.pcap", document.dig("kernel_observation", "packet_trace", "path")
      assert_equal result.fetch("sha256"), document.dig("kernel_observation", "packet_trace", "sha256")
      assert_equal true, document.dig("kernel_observation", "packet_trace", "materialized")
      assert_equal 1, document.dig("kernel_observation", "packet_trace", "parsed_packet_count")
    end
  end

  def test_pcap_parser_rejects_a_global_header_without_records
    Dir.mktmpdir("rubernetes-m4-pcap") do |directory|
      path = File.join(directory, "header-only.pcap")
      File.binwrite(path, pcap_global_header)

      error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(path) }

      assert_match(/no packet records/, error.message)
    end
  end

  def test_pcap_parser_rejects_truncated_record_and_trailing_bytes
    Dir.mktmpdir("rubernetes-m4-pcap") do |directory|
      truncated = File.join(directory, "truncated.pcap")
      trailing = File.join(directory, "trailing.pcap")
      File.binwrite(truncated, pcap_global_header + [1, 0, 8, 8].pack("V4") + "short")
      File.binwrite(trailing, pcap_bytes("PING") + "\x00")

      truncated_error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(truncated) }
      trailing_error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(trailing) }

      assert_match(/truncated/, truncated_error.message)
      assert_match(/trailing bytes/, trailing_error.message)
    end
  end

  def test_pcap_parser_rejects_zero_length_packet_records
    Dir.mktmpdir("rubernetes-m4-pcap") do |directory|
      zero_zero = File.join(directory, "zero-zero.pcap")
      zero_original = File.join(directory, "zero-original.pcap")
      File.binwrite(zero_zero, pcap_global_header + [1, 0, 0, 0].pack("V4"))
      File.binwrite(zero_original, pcap_global_header + [1, 0, 0, 1].pack("V4"))

      zero_zero_error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(zero_zero) }
      zero_original_error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(zero_original) }

      assert_match(/included length must be positive/, zero_zero_error.message)
      assert_match(/included length must be positive/, zero_original_error.message)
    end
  end

  def test_pcapng_parser_counts_epb_and_spb_and_rejects_bad_trailer
    Dir.mktmpdir("rubernetes-m4-pcapng") do |directory|
      valid = File.join(directory, "valid.pcapng")
      invalid = File.join(directory, "bad-trailer.pcapng")
      bytes = pcapng_bytes
      File.binwrite(valid, bytes)
      corrupted = bytes.dup
      corrupted[-4, 4] = [0].pack("V")
      File.binwrite(invalid, corrupted)

      parsed = M34EvidenceSupport.parse_packet_capture(valid)
      error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(invalid) }

      assert_equal "pcapng", parsed.fetch("format")
      assert_equal 2, parsed.fetch("packet_count")
      assert_match(/trailer does not match/, error.message)
    end
  end

  def test_pcapng_magic_without_complete_section_is_rejected
    Dir.mktmpdir("rubernetes-m4-pcapng") do |directory|
      path = File.join(directory, "magic-only.pcapng")
      File.binwrite(path, [0x0a, 0x0d, 0x0d, 0x0a].pack("C4"))

      error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(path) }

      assert_match(/truncated/, error.message)
    end
  end

  def test_pcapng_parser_rejects_zero_length_enhanced_packet
    Dir.mktmpdir("rubernetes-m4-pcapng") do |directory|
      path = File.join(directory, "zero-epb.pcapng")
      section = pcapng_block(
        0x0a0d0d0a,
        [0x1a2b3c4d].pack("V") + [1, 0].pack("v2") + [-1].pack("q<")
      )
      interface = pcapng_block(0x00000001, [1, 0, 65_535].pack("v2V"))
      zero_epb = pcapng_block(0x00000006, [0, 0, 0, 0, 0].pack("V5"))
      File.binwrite(path, section + interface + zero_epb)

      error = assert_raises(RuntimeError) { M34EvidenceSupport.parse_packet_capture(path) }

      assert_match(/captured length must be positive/, error.message)
    end
  end

  def test_gate_rejects_declared_packet_count_that_differs_from_parsed_records
    Dir.mktmpdir("rubernetes-m4-packet-count") do |directory|
      path = File.join(directory, "network.pcap")
      File.binwrite(path, pcap_bytes("PING"))
      digest = Digest::SHA256.file(path).hexdigest
      packet = {
        "format" => "pcap", "path" => "network.pcap", "artifact_path" => "network.pcap",
        "materialized" => true, "bytes" => File.size(path), "size" => File.size(path),
        "sha256" => digest, "packet_count" => 2, "parsed_packet_count" => 2,
        "parser" => "rubernetes-m4-packet-capture-v1", "command" => ["tcpdump"]
      }
      artifacts = [{"path" => "network.pcap", "bytes" => File.size(path), "sha256" => digest}]
      errors = []

      M4Gate.send(:validate_materialized_packet_trace, packet, errors, "network observation",
                  evidence_directory: directory, artifacts: artifacts)

      assert(errors.any? { |error| error.include?("packet_count") && error.include?("parsed records") })
    end
  end

  def test_live_namespace_rejects_claimed_inode_that_differs_from_procfs
    pid = Process.pid
    path = "/proc/#{pid}/ns/net"
    start_time = M4Gate.send(:proc_start_time_ticks, pid)
    actual_inode = File.stat(path).ino
    keeper_identity = {
      "path" => path, "pid" => pid, "runner_pid" => pid,
      "start_time_ticks" => start_time, "netns_inode" => actual_inode + 1
    }
    keeper_digest = M4Gate.canonical_document_digest(keeper_identity)
    runner = {"process_id" => pid, "keeper_pid" => pid, "keeper_start_time_ticks" => start_time,
              "keeper_identity_sha256" => keeper_digest}
    keeper = keeper_identity.merge("identity" => keeper_identity, "identity_sha256" => keeper_digest)
    namespace_identity = {
      "path" => path, "pid" => pid, "runner_pid" => pid, "start_time_ticks" => start_time,
      "inode" => actual_inode + 1, "keeper_identity_sha256" => keeper_digest
    }
    netns = {"path" => path, "pid" => pid, "runner_pid" => pid, "start_time_ticks" => start_time,
             "inode" => actual_inode + 1, "identity" => namespace_identity,
             "identity_sha256" => M4Gate.canonical_document_digest(namespace_identity)}
    errors = []

    M4Gate.send(:validate_live_network_namespace, netns, runner, keeper, errors, "network observation")

    assert(errors.any? { |error| error.include?("inode") && error.include?("/proc readback") })
  end

  def test_live_namespace_rejects_dead_external_runner_even_with_a_live_keeper
    pid = Process.pid
    path = "/proc/#{pid}/ns/net"
    start_time = M4Gate.send(:proc_start_time_ticks, pid)
    inode = File.stat(path).ino
    runner_pid = 999_999_999
    keeper_identity = {
      "path" => path, "pid" => pid, "runner_pid" => runner_pid,
      "start_time_ticks" => start_time, "netns_inode" => inode
    }
    keeper_digest = M4Gate.canonical_document_digest(keeper_identity)
    runner = {
      "process_id" => runner_pid, "start_time_ticks" => 1,
      "keeper_pid" => pid, "keeper_start_time_ticks" => start_time,
      "keeper_identity_sha256" => keeper_digest
    }
    keeper = keeper_identity.merge("identity" => keeper_identity, "identity_sha256" => keeper_digest)
    namespace_identity = {
      "path" => path, "pid" => pid, "runner_pid" => runner_pid,
      "start_time_ticks" => start_time, "inode" => inode,
      "keeper_identity_sha256" => keeper_digest
    }
    netns = {
      "path" => path, "pid" => pid, "runner_pid" => runner_pid,
      "start_time_ticks" => start_time, "inode" => inode,
      "identity" => namespace_identity,
      "identity_sha256" => M4Gate.canonical_document_digest(namespace_identity)
    }
    errors = []

    M4Gate.send(:validate_live_network_namespace, netns, runner, keeper, errors, "network observation")

    assert(errors.any? { |error| error.include?("runner process") })
  end

  def test_bundle_descriptor_walk_rejects_a_renamed_parent_symlink
    Dir.mktmpdir("rubernetes-m4-bundle") do |directory|
      bundle = File.join(directory, "bundle")
      inside = File.join(bundle, "capture")
      outside = File.join(directory, "outside")
      FileUtils.mkdir_p(inside)
      FileUtils.mkdir_p(outside)
      File.binwrite(File.join(inside, "network.pcap"), pcap_bytes("PING"))
      File.binwrite(File.join(outside, "network.pcap"), pcap_bytes("PONG"))

      File.rename(inside, File.join(bundle, "capture-real"))
      File.symlink(outside, inside)

      error = assert_raises(RuntimeError) do
        M34EvidenceSupport.read_bundle_file(bundle, "capture/network.pcap")
      end

      assert_match(/securely opened|Not a directory|symlink/, error.message)
    end
  end

  def test_kernel_object_self_report_cannot_replace_live_readback
    live = {
      "kind" => "link", "id" => "link:eth0",
      "identity" => "link:netns=100:ifindex=2:name=eth0:mac=-",
      "metadata" => {"netns_inode" => 100, "ifindex" => 2}
    }
    forged = live.merge("metadata" => {"netns_inode" => 100, "ifindex" => 999})
    object = {
      "kind" => "link", "id" => "link:eth0", "identity" => forged["identity"], "ifindex" => 999,
      "readback" => forged, "readback_sha256" => M4Gate.canonical_document_digest(forged),
      "identity_sha256" => M4Gate.canonical_document_digest(forged["identity"])
    }
    errors = []

    M4Gate.send(:validate_live_kernel_object, object, 0, [live],
                {"inode" => 100}, errors, "network observation")

    assert(errors.any? { |error| error.include?("differs from the live kernel object") })
    assert(errors.any? { |error| error.include?("live ifindex") })
  end

  def test_node_crash_recovery_rejects_filesystem_adapter_and_unbound_observation
    owner = {"adapter" => {"runner_sha256" => "d" * 64}}
    fake = native_crash_fixture(owner.fetch("adapter").fetch("runner_sha256"))
    fake["measurement_source"] = "external_runner"
    fake["mode"] = "external_runner"
    fake["operation"] = "ControllerPublishVolume"
    fake["mount_adapter_class"] = "Rubernetes::Volume::FilesystemAdapter"
    fake.delete("binding")
    fake.delete("binding_sha256")
    errors = []

    M4Gate.send(:validate_node_crash_recovery, fake, errors, owner_document: owner)

    assert(errors.any? { |error| error.include?("measurement source must be native") })
    assert(errors.any? { |error| error.include?("native mount adapter") })
    assert(errors.any? { |error| error.include?("runner/child/observation binding") })
  end

  def test_node_crash_recovery_accepts_bound_native_mount_namespace_evidence
    owner = {"adapter" => {"runner_sha256" => "e" * 64}}
    evidence = native_crash_fixture(owner.fetch("adapter").fetch("runner_sha256"))
    errors = []

    M4Gate.send(:validate_node_crash_recovery, evidence, errors, owner_document: owner)

    assert_empty errors
  end

  private

  def native_crash_fixture(runner_sha256)
    child = {"pid" => 42, "start_time_ticks" => 1234, "mount_namespace_inode" => 9876,
             "path" => "/proc/42/ns/mnt"}
    target = {"path" => "/var/lib/rubernetes/stage", "device" => 2049, "inode" => 77,
              "mode" => 16_877, "mount_id" => 3001, "device_major_minor" => "8:1",
              "filesystem" => "ext4", "mountinfo_line" => "3001 1 8:1 /src /var/lib/rubernetes/stage rw - ext4 /dev/sda1 rw"}
    effect = {"name" => "native_mount_complete_before_node_record_commit",
              "phase" => "after_effect_before_durable_commit", "operation" => "NodeStageVolume",
              "syscall" => "mount(2)", "observed" => true, "pid" => child.fetch("pid"),
              "start_time_ticks" => child.fetch("start_time_ticks"),
              "mount_namespace_inode" => child.fetch("mount_namespace_inode"),
              "target" => target.fetch("path"), "mount_id" => target.fetch("mount_id"),
              "target_device" => target.fetch("device"), "target_inode" => target.fetch("inode")}
    mountinfo = ["3001 1 8:1 /src /var/lib/rubernetes/stage rw - ext4 /dev/sda1 rw"]
    observation = {"operation" => "NodeStageVolume", "child" => child, "effect_boundary" => effect,
                   "target" => target, "mountinfo" => mountinfo}
    restart_child = {"pid" => 43, "start_time_ticks" => 1235, "mount_namespace_inode" => 9877,
                     "path" => "/proc/43/ns/mnt"}
    restart_stage = target.merge("path" => "/var/lib/rubernetes/stage-restart", "mount_id" => 3002,
                                 "mountinfo_line" => "3002 1 8:1 /src /var/lib/rubernetes/stage-restart rw - ext4 /dev/sda1 rw")
    restart_publish = target.merge("path" => "/var/lib/rubernetes/publish-restart", "mount_id" => 3003,
                                   "mountinfo_line" => "3003 1 8:1 /src /var/lib/rubernetes/publish-restart rw - ext4 /dev/sda1 rw")
    restart_mountinfo = [restart_stage.fetch("mountinfo_line"), restart_publish.fetch("mountinfo_line")]
    restart_observation = {"operation" => %w[NodeStageVolume NodePublishVolume], "child" => restart_child,
                           "stage_target" => restart_stage, "publish_target" => restart_publish,
                           "mountinfo" => restart_mountinfo, "recovery_unknown_count" => 0}
    restart_marker = {"passed" => true, "measurement_source" => "native_mount_namespace",
                      "operations" => %w[NodeStageVolume NodePublishVolume],
                      "observation" => restart_observation,
                      "observation_sha256" => M4Gate.canonical_document_digest(restart_observation),
                      "child_identity_sha256" => M4Gate.canonical_document_digest(restart_child),
                      "mountinfo_sha256" => Digest::SHA256.hexdigest(restart_mountinfo.join("\n"))}
    evidence = {"passed" => true, "available" => true, "measurement_source" => "native_mount_namespace",
                "mode" => "native_mount_namespace", "operation" => "NodeStageVolume",
                "mount_adapter_class" => "Rubernetes::Volume::NativeMountAdapter",
                "backend_adapter_class" => "Rubernetes::Volume::FilesystemAdapter",
                "runner_sha256" => runner_sha256,
                "child_identity_sha256" => M4Gate.canonical_document_digest(child),
                "target_identity_sha256" => M4Gate.canonical_document_digest(target),
                "effect_boundary_sha256" => M4Gate.canonical_document_digest(effect),
                "observation" => observation,
                "observation_sha256" => M4Gate.canonical_document_digest(observation),
                "mountinfo_sha256" => Digest::SHA256.hexdigest(mountinfo.join("\n")),
                "signal" => "SIGKILL",
                "child_killed" => true,
                "restart" => {"performed" => true, "marker" => restart_marker}}
    binding = {"runner_sha256" => runner_sha256, "child_identity_sha256" => evidence.fetch("child_identity_sha256"),
               "observation_sha256" => evidence.fetch("observation_sha256")}
    evidence["binding"] = binding
    evidence["binding_sha256"] = M4Gate.canonical_document_digest(binding)
    evidence["recovery"] = {"unknown_count" => 0, "state_after_recovery" => "Attached", "errors" => []}
    evidence["cleanup_passed"] = true
    evidence
  end

  def pcap_global_header
    [0xd4, 0xc3, 0xb2, 0xa1].pack("C4") +
      [2, 4, 0, 0, 65_535, 1].pack("v2 V4")
  end

  def pcap_bytes(payload)
    value = ethernet_frame(payload)
    pcap_global_header + [1, 0, value.bytesize, value.bytesize].pack("V4") + value
  end

  def ethernet_frame(payload)
    ("\x00" * 12).b + [0x0800].pack("n") + payload.to_s.b
  end

  def pcapng_block(type, body)
    payload = body.to_s.b
    raise "test PCAPNG body must be aligned" unless (payload.bytesize % 4).zero?

    total = 12 + payload.bytesize
    [type, total].pack("V2") + payload + [total].pack("V")
  end

  def pcapng_bytes
    section = pcapng_block(
      0x0a0d0d0a,
      [0x1a2b3c4d].pack("V") + [1, 0].pack("v2") + [-1].pack("q<")
    )
    interface = pcapng_block(0x00000001, [1, 0, 65_535].pack("v2V"))
    enhanced_payload = ethernet_frame("PING")
    enhanced_padding = "\0" * ((4 - (enhanced_payload.bytesize % 4)) % 4)
    enhanced = pcapng_block(0x00000006,
                            [0, 0, 0, enhanced_payload.bytesize,
                             enhanced_payload.bytesize].pack("V5") + enhanced_payload + enhanced_padding)
    simple_payload = ethernet_frame("END")
    simple_padding = "\0" * ((4 - (simple_payload.bytesize % 4)) % 4)
    simple = pcapng_block(0x00000003, [simple_payload.bytesize].pack("V") + simple_payload + simple_padding)
    section + interface + enhanced + simple
  end
end
