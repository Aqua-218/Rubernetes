# frozen_string_literal: true

require "digest"
require "English"
require "json"
require "time"
require "uri"
require_relative "../../lib/rubernetes/cluster"

module Conformance
  # Cilium's DaemonSet writes one CNI configuration, one bpffs tree and one
  # set of host routes per node. Give it a whole guest with one real worker
  # and no Rubernetes bridge IPAM. Rubernetes still owns the Service proxy.
  class K6CiliumGuest < Rubernetes::Cluster::Provisioner
    def node_advertise_addresses(_index) = [host_advertise_address]

    def write_agent_config(...)
      path = super
      document = YAML.safe_load_file(path)
      agent = document.dig("processes", "rubernetes-agent")
      agent.fetch("network")["plugin"] = "cni"
      dns_address = host_advertise_address
      agent.fetch("dns").merge!("bind_addresses" => [dns_address], "cluster_dns" => [dns_address])
      File.write(path, YAML.dump(document))
      path
    end

    def self.run(evidence)
      boot_id = File.read("/proc/sys/kernel/random/boot_id").strip
      vendor = File.read("/sys/class/dmi/id/sys_vendor").strip
      abort "Cilium requires its dedicated QEMU guest" unless vendor == "QEMU" && ENV["RUBERNETES_K6_CILIUM_GUEST"] == boot_id

      FileUtils.mkdir_p(evidence)
      cluster = new(root: "/srv/k6-cilium", controls: 1, workers: 1, datastore: "memory", identities: :components,
                    cgroup_root: "/sys/fs/cgroup/k6-cilium",
                    descriptor: {"kind" => "conformance_cluster", "cilium_guest_boot_id" => boot_id})
      descriptor = cluster.up
      File.write(File.join(evidence, "up.json"), JSON.pretty_generate(descriptor))
      env = {
        "RUBERNETES_K6_CILIUM_API_PORT" => URI(descriptor.fetch("endpoint")).port.to_s,
        "RUBERNETES_K6_CILIUM_EVIDENCE" => File.expand_path(evidence),
        "RUBERNETES_K6_CILIUM_VALUES" => File.expand_path("../../test/compatibility/projects/values/cilium-guest.yml", __dir__)
      }
      command = [RbConfig.ruby, File.join(__dir__, "k6_corpus.rb"), "--projects-only", "--cleanup-retained-crds",
                 "--only", "cilium", "--kubeconfig", descriptor.fetch("kubeconfig"), "--output", File.join(evidence, "output")]
      input_paths = %w[tools/conformance/k6_corpus.rb tools/conformance/k6_cilium_guest.rb tools/conformance/k6_cilium_runtime.rb
                       tools/conformance/k6_project_runtime_residue.rb tools/conformance/k6_project_residue.rb
                       tools/conformance/k6_project_images.rb tools/conformance/k6_project_pod_watch.rb
                       lib/rubernetes/network/native_observer.rb lib/rubernetes/network/netlink.rb test/compatibility/projects/corpus.yml
                       test/compatibility/projects/smoke/cilium.sh test/compatibility/projects/values/cilium-guest.yml]
      inputs = input_paths.to_h { |path| [path, Digest::SHA256.file(File.expand_path("../../#{path}", __dir__)).hexdigest] }
      started = Time.now.utc.iso8601(6)
      passed = system(env, *command)
      receipt = {"command" => command, "started_at" => started, "finished_at" => Time.now.utc.iso8601(6),
                 "exit_status" => $CHILD_STATUS&.exitstatus, "boot_id" => boot_id, "input_sha256" => inputs}
      File.write(File.join(evidence, "cilium-command.json"), JSON.pretty_generate(receipt))
      passed
    ensure
      if cluster
        File.write(File.join(evidence, "down.json"), JSON.pretty_generate(cluster.down))
        logs = File.join(cluster.root, "logs")
        FileUtils.cp_r(logs, evidence) if File.directory?(logs)
      end
    end
  end
end

exit(Conformance::K6CiliumGuest.run(ARGV.fetch(0))) if $PROGRAM_NAME == __FILE__
