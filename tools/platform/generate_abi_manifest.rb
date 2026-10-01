#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "shellwords"
require "tmpdir"

module Rubernetes
  module Tools
    # Generates the per-architecture Linux ABI manifest under
    # generated/platform/linux/abi/: struct sizes/alignments, the constants
    # the platform adapters use, and the complete syscall number table from
    # the architecture's UAPI headers.
    #
    # Syscall numbers are never taken from the running Ruby process.  The
    # names come from the architecture's `asm/unistd*.h` (every `__NR_*` the
    # header defines) and their values from the C preprocessor, so a
    # cross-compiler can produce the table for an architecture this host
    # cannot execute (`--architecture aarch64 --cc aarch64-linux-gnu-gcc
    # --update PATH` refreshes only the syscall tables of an existing
    # manifest; the layouts and constants of a foreign architecture come from
    # a probe run on that architecture).
    class GenerateABIManifest
      ARCHITECTURES = {"x86_64" => "x86_64", "amd64" => "x86_64", "aarch64" => "aarch64", "arm64" => "aarch64"}.freeze
      SYSCALL_HEADERS = {
        "x86_64" => %w[/usr/include/x86_64-linux-gnu/asm/unistd_64.h /usr/include/asm/unistd_64.h],
        "aarch64" => %w[/usr/aarch64-linux-gnu/include/asm-generic/unistd.h /usr/include/asm-generic/unistd.h]
      }.freeze
      # Header macros that are not syscalls.
      EXCLUDED_NAMES = %w[syscalls arch_specific_syscall].freeze
      HEAD = <<~'C'
        #include <asm/unistd.h>
        #include <endian.h>
        #include <linux/bpf.h>
        #include <linux/kvm.h>
        #include <linux/netlink.h>
        #include <linux/rtnetlink.h>
        #include <linux/sched.h>
        #include <linux/version.h>
        #include <stdalign.h>
        #include <stdint.h>
        #include <stdio.h>
        #include <sys/mount.h>

        #define VALUE(name, value) printf(name "=%llu\n", (unsigned long long)(value))
        #define LAYOUT(name, type) do { \
          printf("structures." name ".size=%zu\n", sizeof(type)); \
          printf("structures." name ".alignment=%zu\n", alignof(type)); \
        } while (0)

        int main(void) {
          VALUE("linux_version_code", LINUX_VERSION_CODE);
          VALUE("word_size", sizeof(void *) * 8);
          VALUE("little_endian", __BYTE_ORDER == __LITTLE_ENDIAN);
          VALUE("syscalls.clone3", __NR_clone3);
          VALUE("syscalls.pidfd_open", __NR_pidfd_open);
          VALUE("syscalls.pidfd_send_signal", __NR_pidfd_send_signal);
          VALUE("syscalls.mount", __NR_mount);
          VALUE("syscalls.umount2", __NR_umount2);
          VALUE("syscalls.bpf", __NR_bpf);
          /*
           * The seccomp syscall table is the complete set of __NR_* names the
           * architecture's UAPI header defines.  The Ruby security planner is
           * deliberately not allowed to infer syscall numbers from the running
           * process: an architecture profile must carry the numbers obtained
           * from the matching headers.  Each emission is guarded so a name the
           * compiler's headers lack is omitted rather than invented.
           */
      C
      TAIL = <<~C
          LAYOUT("clone_args", struct clone_args);
          LAYOUT("nlmsghdr", struct nlmsghdr);
          LAYOUT("sockaddr_nl", struct sockaddr_nl);
          LAYOUT("bpf_insn", struct bpf_insn);
          LAYOUT("bpf_attr", union bpf_attr);
          LAYOUT("kvm_userspace_memory_region", struct kvm_userspace_memory_region);
          VALUE("constants.clone.CLONE_PIDFD", CLONE_PIDFD);
          VALUE("constants.clone.CLONE_NEWNS", CLONE_NEWNS);
          VALUE("constants.clone.CLONE_NEWPID", CLONE_NEWPID);
          VALUE("constants.netlink.NLM_F_REQUEST", NLM_F_REQUEST);
          VALUE("constants.netlink.NLM_F_ACK", NLM_F_ACK);
          VALUE("constants.netlink.NLMSG_ERROR", NLMSG_ERROR);
          VALUE("constants.netlink.RTM_GETLINK", RTM_GETLINK);
          VALUE("constants.bpf.BPF_PROG_LOAD", BPF_PROG_LOAD);
          VALUE("constants.bpf.BPF_PROG_TYPE_SOCKET_FILTER", BPF_PROG_TYPE_SOCKET_FILTER);
          VALUE("constants.kvm.KVM_GET_API_VERSION", KVM_GET_API_VERSION);
          VALUE("constants.kvm.KVM_CHECK_EXTENSION", KVM_CHECK_EXTENSION);
          VALUE("constants.mount.MS_NOSUID", MS_NOSUID);
          VALUE("constants.mount.MS_NODEV", MS_NODEV);
          VALUE("constants.mount.MS_NOEXEC", MS_NOEXEC);
          return 0;
        }
      C

      def initialize(arguments)
        @options = {cc: ENV.fetch("CC", "cc"), output: nil, check: nil, update: nil, architecture: nil, header: nil}
        OptionParser.new do |parser|
          parser.banner = "Usage: generate_abi_manifest.rb [--output PATH | --check PATH | --update PATH] [--architecture ARCH] [--cc COMMAND] " \
                          "[--syscall-header PATH]"
          parser.on("--cc COMMAND", "C compiler executable") { |value| @options[:cc] = value }
          parser.on("--architecture ARCH", "target architecture (default: host)") { |value| @options[:architecture] = value }
          parser.on("--syscall-header PATH", "UAPI unistd header naming the syscalls") { |value| @options[:header] = value }
          parser.on("--output PATH", "write the generated manifest") { |value| @options[:output] = value }
          parser.on("--check PATH", "compare generated ABI values with PATH") { |value| @options[:check] = value }
          parser.on("--update PATH", "refresh only the syscall tables of the manifest at PATH (cross-compiler mode)") do |value|
            @options[:update] = value
          end
        end.parse!(arguments)
        modes = %i[output check update].count { |key| @options[key] }
        raise OptionParser::InvalidOption, "--output, --check and --update are mutually exclusive" if modes > 1
      end

      def run
        if @options[:update]
          document = JSON.pretty_generate(update(JSON.parse(File.read(@options[:update])))) << "\n"
          File.write(@options[:update], document)
          return 0
        end

        manifest = generate
        if @options[:check]
          expected = JSON.parse(File.read(@options[:check]))
          return check(expected, manifest)
        end

        document = JSON.pretty_generate(manifest) << "\n"
        if @options[:output]
          FileUtils.mkdir_p(File.dirname(@options[:output]))
          File.write(@options[:output], document)
        else
          $stdout.write(document)
        end
        0
      rescue Errno::ENOENT, JSON::ParserError, RuntimeError => error
        warn(error.message)
        1
      end

      # The complete probe source for an architecture.
      def self.source_for(architecture, header: nil)
        names = syscall_names(architecture, header: header)
        body = names.map do |name|
          "#ifdef __NR_#{name}\n          VALUE(\"seccomp_syscalls.#{name}\", __NR_#{name});\n#endif\n"
        end.join
        HEAD + body + TAIL
      end

      # Every `__NR_<name>` the architecture's UAPI header defines.
      def self.syscall_names(architecture, header: nil)
        path = header || SYSCALL_HEADERS.fetch(architecture).find { |candidate| File.file?(candidate) }
        raise "no unistd header found for #{architecture}; pass --syscall-header" if path.nil?

        File.read(path).scan(/^#define\s+__NR_([A-Za-z0-9_]+)\b/).flatten.uniq.reject do |name|
          EXCLUDED_NAMES.include?(name) || name.start_with?("3264_")
        end.sort
      end

      private

      def architecture
        requested = @options[:architecture] || RbConfig::CONFIG.fetch("host_cpu")
        ARCHITECTURES.fetch(requested.to_s.downcase) { raise "unsupported architecture #{requested.inspect}" }
      end

      def source
        @source ||= self.class.source_for(architecture, header: @options[:header])
      end

      def compiler
        command = Shellwords.split(@options[:cc])
        raise "C compiler command is empty" if command.empty?

        command
      end

      def generate
        output = nil
        Dir.mktmpdir("rubernetes-abi-") do |directory|
          source_path = File.join(directory, "probe.c")
          binary_path = File.join(directory, "probe")
          File.write(source_path, source)
          _stdout, compile_error, status = Open3.capture3(
            *compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", source_path, "-o", binary_path
          )
          raise "ABI probe compilation failed: #{compile_error}" unless status.success?

          output, execute_error, status = Open3.capture3(binary_path)
          raise "ABI probe execution failed: #{execute_error}" unless status.success?
        end
        values = output.lines.to_h do |line|
          key, value = line.strip.split("=", 2)
          [key, Integer(value)]
        end
        host = ARCHITECTURES.fetch(RbConfig::CONFIG.fetch("host_cpu")) { raise "unsupported host architecture" }
        raise "the probe binary can only be executed for the host architecture (#{host}); use --update for #{architecture}" unless host == architecture

        # Both routes must agree on every syscall number the header defines.
        preprocessed = preprocessed_syscalls
        probed = nested(values, "seccomp_syscalls")
        disagreements = probed.select { |name, number| preprocessed.key?(name) && preprocessed[name] != number }
        raise "probe and preprocessor disagree on #{disagreements.keys.join(", ")}" unless disagreements.empty?

        {
          "schema_version" => 1,
          "architecture" => architecture,
          "word_size" => values.fetch("word_size"),
          "byte_order" => values.fetch("little_endian") == 1 ? "little" : "big",
          "source" => {
            "kind" => "linux_uapi_headers",
            "linux_version_code" => values.fetch("linux_version_code"),
            "probe_sha256" => Digest::SHA256.hexdigest(source),
            "syscall_count" => probed.length
          },
          "syscalls" => nested(values, "syscalls"),
          "seccomp_syscalls" => probed,
          "structures" => structure_values(values),
          "constants" => constant_values(values)
        }
      end

      # Cross-compiler mode: replace the syscall tables of an existing
      # manifest with the target architecture's preprocessor results.
      def update(manifest)
        unless manifest["architecture"] == architecture
          raise "manifest architecture #{manifest["architecture"].inspect} does not match --architecture #{architecture}"
        end

        table = preprocessed_syscalls
        core = %w[clone3 pidfd_open pidfd_send_signal mount umount2 bpf].to_h do |name|
          [name, table.fetch(name) { raise "#{architecture} header does not define __NR_#{name}" }]
        end
        manifest.merge(
          "source" => manifest.fetch("source").merge("probe_sha256" => Digest::SHA256.hexdigest(source), "syscall_count" => table.length),
          "syscalls" => core,
          "seccomp_syscalls" => table
        )
      end

      # `NAME=__NR_NAME` lines through `cc -E`: a defined name expands to its
      # number, an undefined one stays as written and is dropped.
      def preprocessed_syscalls
        names = self.class.syscall_names(architecture, header: @options[:header])
        program = "#include <asm/unistd.h>\n" + names.map { |name| "#{name}=__NR_#{name}\n" }.join
        stdout, stderr, status = Open3.capture3(*compiler, "-E", "-P", "-x", "c", "-", stdin_data: program)
        raise "syscall preprocessing failed: #{stderr}" unless status.success?

        stdout.lines.each_with_object({}) do |line, table|
          name, expression = line.strip.split("=", 2)
          next if expression.nil? || expression.include?("__NR_")

          value = evaluate(expression)
          table[name] = value unless value.nil?
        end.sort.to_h
      end

      # Header values are integer literals or parenthesised sums of them.
      def evaluate(expression)
        text = expression.strip
        return nil unless text.match?(/\A[\s()0-9xXa-fA-F+-]+\z/)
        return nil if text.empty?

        Integer(eval(text.gsub(/\b0[xX]([0-9a-fA-F]+)\b/) { ::Regexp.last_match(1).to_i(16).to_s }), exception: false) # rubocop:disable Security/Eval
      rescue StandardError
        nil
      end

      def nested(values, prefix)
        values.filter_map do |key, value|
          next unless key.start_with?("#{prefix}.")

          [key.delete_prefix("#{prefix}."), value]
        end.to_h.sort.to_h
      end

      def structure_values(values)
        values.filter_map { |key, _value| key.split(".", 3)[1] if key.start_with?("structures.") }.uniq.sort.to_h do |name|
          [
            name,
            {
              "size" => values.fetch("structures.#{name}.size"),
              "alignment" => values.fetch("structures.#{name}.alignment")
            }
          ]
        end
      end

      def constant_values(values)
        result = {}
        values.each do |key, value|
          next unless key.start_with?("constants.")

          _prefix, group, name = key.split(".", 3)
          (result[group] ||= {})[name] = value
        end
        result.sort.to_h.transform_values { |group| group.sort.to_h }
      end

      def check(expected, actual)
        source_matches = expected.dig("source", "probe_sha256") == Digest::SHA256.hexdigest(source)
        canonical_expected = JSON.pretty_generate(expected) << "\n"
        byte_matches = File.binread(@options[:check]) == canonical_expected
        if expected == actual && source_matches && byte_matches
          puts("ABI manifest matches #{File.expand_path(@options[:check])}")
          return 0
        end

        warn("ABI manifest mismatch for #{File.expand_path(@options[:check])}")
        warn(JSON.pretty_generate(expected: expected, actual: actual, source_matches: source_matches, byte_matches: byte_matches))
        1
      end
    end
  end
end

exit Rubernetes::Tools::GenerateABIManifest.new(ARGV).run if $PROGRAM_NAME == __FILE__
