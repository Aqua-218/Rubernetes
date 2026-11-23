# frozen_string_literal: true

require "digest"
require "tempfile"

# An adapter's stdout is already the bundle's report file. For large reports,
# retain one exact copy and bind the command to its verified artifact entry.
module MilestoneReportOutput
  EMBEDDED_LIMIT = 64 * 1024

  def self.capture(path, environment, command, chdir:)
    Tempfile.create([".report-", ".pending"], File.dirname(path)) do |file|
      stderr, status = IO.pipe do |reader, writer|
        pid = Process.spawn(environment, *command, chdir: chdir, in: File::NULL, out: file, err: writer)
        waiter = Process.detach(pid)
        writer.close
        [reader.read, waiter.value]
      end

      size = file.size
      output = if size <= EMBEDDED_LIMIT
                 file.rewind
                 {"stdout" => file.read}
               else
                 {"stdout" => "", "stdout_sha256" => Digest::SHA256.file(file.path).hexdigest,
                  "stdout_bytes" => size, "stdout_artifact" => File.basename(path)}
               end
      file.chmod(File.exist?(path) ? File.stat(path).mode & 0o777 : 0o666 & ~File.umask)
      File.rename(file.path, path)
      [output, stderr, status]
    end
  end

  def self.validate(commands, artifacts, errors)
    return unless commands.is_a?(Array)

    commands.each do |command|
      next unless command.is_a?(Hash) && command.key?("stdout_artifact")

      path = command["stdout_artifact"]
      artifact = artifacts.find { |entry| entry["path"] == path }
      next if artifact && command["stdout"] == "" && command["stdout_sha256"] == artifact["sha256"] &&
              command["stdout_bytes"].is_a?(Integer) && command["stdout_bytes"] == artifact["bytes"]

      errors << "command #{command["name"]} stdout does not match its report artifact"
    end
  end
end
