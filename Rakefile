# frozen_string_literal: true

require "rake/testtask"
require "fileutils"
require "rbconfig"
require "shellwords"
require_relative "lib/rubernetes/version"

Rake::TestTask.new(:test) do |task|
  task.libs << "lib"
  task.libs << "test"
  task.libs << "build/ext/rubernetes_linux"
  task.pattern = "test/**/*_test.rb"
  task.warning = true
end

task default: :test

desc "RuboCop over the whole tree (.rubocop.yml; historical offenses in .rubocop_todo.yml)"
task :lint do
  ruby "-e", 'load Gem.bin_path("rubocop", "rubocop")', "--", "--parallel"
end

namespace :lint do
  desc "RuboCop with safe autocorrect"
  task :fix do
    ruby "-e", 'load Gem.bin_path("rubocop", "rubocop")', "--", "--autocorrect"
  end
end

namespace :test do
  desc "Full suite, one process per file, N at a time (developer fast lane; evidence uses `rake test`)"
  task :parallel do
    jobs = ENV["JOBS"] ? ["--jobs", ENV.fetch("JOBS")] : []
    sh RbConfig.ruby, "tools/test/parallel_runner.rb", *jobs
  end
end

namespace :abi do
  desc "Regenerate the ABI manifest for the current architecture"
  task :generate do
    architecture = RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64")
    sh RbConfig.ruby,
       "tools/platform/generate_abi_manifest.rb",
       "--output",
       "generated/platform/linux/abi/#{architecture}.json"
  end

  desc "Verify the checked-in ABI manifest against host kernel headers"
  task :verify do
    architecture = RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64")
    sh RbConfig.ruby,
       "tools/platform/generate_abi_manifest.rb",
       "--check",
       "generated/platform/linux/abi/#{architecture}.json"
  end
end

desc "Build the Linux ABI shim under build/"
task :compile do
  build_directory = File.expand_path("build/ext/rubernetes_linux", __dir__)
  FileUtils.mkdir_p(build_directory)
  Dir.chdir(build_directory) do
    sh RbConfig.ruby, File.expand_path("ext/rubernetes_linux/extconf.rb", __dir__)
    sh ENV.fetch("MAKE", "make")
  end
end

task test: :compile

namespace :m0 do
  desc "Build the M0 gem under build/"
  task :gem_build do
    FileUtils.mkdir_p("build")
    sh "gem", "build", "rubernetes.gemspec", "--output", "build/rubernetes-#{Rubernetes::VERSION}.gem"
  end

  desc "Check all executable help and version paths"
  task :executables do
    sh RbConfig.ruby, "tools/milestones/executables_probe.rb"
  end

  desc "Scan the native boundary for forbidden policy"
  task :native_scan do
    sh RbConfig.ruby, "tools/milestones/native_boundary_scan.rb"
  end

  desc "Run the privileged stage-00 kernel probe"
  task kernel: [:compile] do
    ruby_options = ["-Ibuild/ext/rubernetes_linux"]
    sh RbConfig.ruby, *ruby_options, "tools/milestones/m0_kernel_probe.rb"
  end

  desc "Run local, non-privileged M0 verification"
  task verify: [:gem_build, :test, "abi:verify", "rbs:validate", :executables, :native_scan]

  desc "Capture strict M0 evidence (requires stable input and an x86_64 kernel probe)"
  task evidence: [:compile] do
    sh RbConfig.ruby,
       "-Ibuild/ext/rubernetes_linux",
       "tools/milestones/m0_evidence.rb"
  end
end

namespace :m1 do
  probe_commands = %w[corpus generation roundtrip api kubectl].to_h do |name|
    [name, Shellwords.join([RbConfig.ruby, File.expand_path("tools/milestones/m1_#{name}_probe.rb", __dir__)])]
  end.freeze

  desc "Capture strict M1 schema/API evidence from the five real adapters"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m1_evidence.rb"]
    probe_commands.each do |name, adapter|
      command.push("--#{name}-command", adapter)
    end
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M1 evidence gate"
  task verify: ["m0:verify", :test, :evidence]
end

namespace :m2 do
  desc "Run the real-kernel M2 adapter for the x86_64 release target"
  task kernel: [:compile] do
    sh RbConfig.ruby, "-Ibuild/ext/rubernetes_linux", "tools/milestones/m2_kernel_probe.rb"
  end

  desc "Capture strict M2 Native Pod evidence from the five adapters"
  task evidence: [:compile] do
    command = [RbConfig.ruby, "tools/milestones/m2_evidence.rb"]
    command.push("--m0-manifest", ENV.fetch("RUBERNETES_M2_M0_MANIFEST")) if ENV["RUBERNETES_M2_M0_MANIFEST"]
    command.push("--m1-manifest", ENV.fetch("RUBERNETES_M2_M1_MANIFEST")) if ENV["RUBERNETES_M2_M1_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M2 evidence gate"
  task verify: %i[test evidence]
end

namespace :m3 do
  desc "Capture strict M3 controller, scheduler, leader, and watch evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m3_evidence.rb"]
    command.push("--m0-manifest", ENV.fetch("RUBERNETES_M3_M0_MANIFEST")) if ENV["RUBERNETES_M3_M0_MANIFEST"]
    command.push("--m1-manifest", ENV.fetch("RUBERNETES_M3_M1_MANIFEST")) if ENV["RUBERNETES_M3_M1_MANIFEST"]
    command.push("--m2-manifest", ENV.fetch("RUBERNETES_M3_M2_MANIFEST")) if ENV["RUBERNETES_M3_M2_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M3 evidence gate"
  task verify: %i[test evidence]
end

namespace :m4 do
  desc "Capture strict M4 network, policy, proxy, volume, and mount-security evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m4_evidence.rb"]
    command.push("--m0-manifest", ENV.fetch("RUBERNETES_M4_M0_MANIFEST")) if ENV["RUBERNETES_M4_M0_MANIFEST"]
    command.push("--m1-manifest", ENV.fetch("RUBERNETES_M4_M1_MANIFEST")) if ENV["RUBERNETES_M4_M1_MANIFEST"]
    command.push("--m2-manifest", ENV.fetch("RUBERNETES_M4_M2_MANIFEST")) if ENV["RUBERNETES_M4_M2_MANIFEST"]
    command.push("--m3-manifest", ENV.fetch("RUBERNETES_M4_M3_MANIFEST")) if ENV["RUBERNETES_M4_M3_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M4 evidence gate"
  task verify: %i[test evidence]
end

namespace :m5 do
  desc "Capture strict M5 Raft linearizability, fault-matrix, corruption, RTO/RPO, and ownership evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m5_evidence.rb"]
    command.push("--m4-manifest", ENV.fetch("RUBERNETES_M5_M4_MANIFEST")) if ENV["RUBERNETES_M5_M4_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M5 evidence gate"
  task verify: %i[test evidence]
end

namespace :m6 do
  desc "Capture strict M6 API-coverage, feature-gate, CRD/aggregation, webhook, security-pipeline, and fuzz evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m6_evidence.rb"]
    command.push("--m5-manifest", ENV.fetch("RUBERNETES_M6_M5_MANIFEST")) if ENV["RUBERNETES_M6_M5_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M6 evidence gate"
  task verify: %i[test evidence]
end

namespace :m9 do
  desc "Generate the release artifacts: SBOM, release manifest, Ruby LOC, reproducibility, security"
  task :artifacts do
    sh(RbConfig.ruby, "tools/release/sbom.rb")
    sh(RbConfig.ruby, "tools/release/loc_report.rb")
    sh(RbConfig.ruby, "tools/release/reproduce.rb")
    sh(RbConfig.ruby, "tools/release/security_report.rb")
    sh(RbConfig.ruby, "tools/release/release_manifest.rb")
  end

  desc "Run the release performance benchmark against a Kubernetes v1.36.2 oracle"
  task :benchmark do
    command = [RbConfig.ruby, "tools/release/benchmark.rb"]
    command.push("--kubeconfig", ENV.fetch("RUBERNETES_BENCH_KUBECONFIG")) if ENV["RUBERNETES_BENCH_KUBECONFIG"]
    command.push("--oracle-kubeconfig", ENV.fetch("RUBERNETES_BENCH_ORACLE_KUBECONFIG")) if ENV["RUBERNETES_BENCH_ORACLE_KUBECONFIG"]
    sh(*command)
  end

  desc "Run the 72-hour soak (RUBERNETES_SOAK_HOURS overrides only for a dry run)"
  task :soak do
    command = [RbConfig.ruby, "tools/release/soak.rb"]
    command.push("--kubeconfig", ENV.fetch("RUBERNETES_SOAK_KUBECONFIG")) if ENV["RUBERNETES_SOAK_KUBECONFIG"]
    sh(*command)
  end

  desc "Capture strict M9 release, formal, operations, and supply-chain evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m9_evidence.rb"]
    command.push("--m8-manifest", ENV.fetch("RUBERNETES_M9_M8_MANIFEST")) if ENV["RUBERNETES_M9_M8_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M9 release gate"
  task verify: %i[test evidence]
end

namespace :m8 do
  desc "Run the K0-K7 Kubernetes compatibility lanes against a cluster"
  task :lanes do
    command = [RbConfig.ruby, "tools/conformance/run.rb"]
    command.push("--profile", ENV["RUBERNETES_M8_PROFILE"]) if ENV["RUBERNETES_M8_PROFILE"]
    command.push("--lanes", ENV["RUBERNETES_M8_LANES"]) if ENV["RUBERNETES_M8_LANES"]
    command.push("--kubeconfig", ENV["RUBERNETES_CONFORMANCE_KUBECONFIG"]) if ENV["RUBERNETES_CONFORMANCE_KUBECONFIG"]
    if ENV["RUBERNETES_CONFORMANCE_ORACLE_KUBECONFIG"]
      command.push("--oracle-kubeconfig",
                      ENV["RUBERNETES_CONFORMANCE_ORACLE_KUBECONFIG"])
    end
    sh(*command)
  end

  desc "Install the pinned conformance runners (hydrophone, sonobuoy) into build/conformance/bin"
  task :tools do
    sh(RbConfig.ruby, "tools/conformance/install_tools.rb")
  end

  desc "Build the upstream e2e.test binary from the pinned Kubernetes checkout"
  task :e2e_build do
    command = [RbConfig.ruby, "tools/conformance/build_e2e.rb"]
    command.push("--source-root", ENV["RUBERNETES_KUBERNETES_SOURCE"]) if ENV["RUBERNETES_KUBERNETES_SOURCE"]
    sh(*command)
  end

  desc "Rebuild the K3 selection ledger from a Ginkgo dry-run inventory"
  task :selection_ledger do
    inventory = ENV.fetch("RUBERNETES_M8_E2E_INVENTORY")
    sh(RbConfig.ruby, "tools/conformance/build_selection_ledger.rb", "--inventory", inventory)
  end

  desc "Capture strict M8 conformance, selection, corpus, and integrity evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m8_evidence.rb"]
    command.push("--m7-manifest", ENV.fetch("RUBERNETES_M8_M7_MANIFEST")) if ENV["RUBERNETES_M8_M7_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M8 evidence gate"
  task verify: %i[test evidence]
end

namespace :m7 do
  desc "Capture strict M7 KVM L4/L5, attack-matrix, identity, snapshot-corruption, and startup-latency evidence"
  task :evidence do
    command = [RbConfig.ruby, "tools/milestones/m7_evidence.rb"]
    command.push("--m6-manifest", ENV.fetch("RUBERNETES_M7_M6_MANIFEST")) if ENV["RUBERNETES_M7_M6_MANIFEST"]
    sh(*command)
  end

  desc "Run tests and the strict content-addressed M7 evidence gate"
  task verify: %i[test evidence]

  desc "Build the pinned guest kernel and guest artifacts and rewrite the M7 artifact lock"
  task :artifacts do
    sh "sh", "tools/microvm/build_guest_kernel.sh"
    sh RbConfig.ruby, "tools/microvm/build_guest_artifacts.rb"
  end
end

namespace :rbs do
  desc "Validate the hand-authored RBS baseline"
  task :validate do
    sh "bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"
  end
end

# Repository recording: turn whatever the work tree changed into commits, one
# per edit, named after the declaration it lands in (tools/repo/auto_commit.rb).
namespace :repo do
  desc "Record every change in the work tree as commits (AUTO_COMMIT_ARGS adds recorder flags)"
  task :commit do
    args = ENV.fetch("AUTO_COMMIT_ARGS", "").split
    sh RbConfig.ruby, "tools/repo/auto_commit.rb", *args
  end

  desc "Run a rake task, then record what it changed: rake \"repo:record[test:parallel]\""
  task :record, [:task] do |_t, arguments|
    name = arguments[:task] or abort("usage: rake \"repo:record[<task>]\"")
    status = 0
    begin
      Rake::Task[name].invoke
    rescue StandardError, SystemExit => error
      status = error.respond_to?(:status) ? error.status.to_i : 1
      warn "repo:record: #{name} failed (#{error.class}: #{error.message}); recording anyway"
    end
    args = ENV.fetch("AUTO_COMMIT_ARGS", "").split
    sh RbConfig.ruby, "tools/repo/auto_commit.rb", "--cycle", name, "--status", status.to_s, *args
    exit(status) unless status.zero?
  end
end
