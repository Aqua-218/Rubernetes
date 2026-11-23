# frozen_string_literal: true

require "digest"
require "rubygems/version"

module K7Release
  def release_upgrade
    replace_release(:upgrade)
  end

  def rollback
    replace_release(:rollback)
  end

  def replace_release(direction)
    previous = ENV.fetch("RUBERNETES_K7_PREVIOUS_BIN_DIR", nil)
    target = ENV.fetch("RUBERNETES_K7_TARGET_BIN_DIR", nil)
    unless previous && target
      raise K7ClusterDriver::Unsupported, "supply two installed releases with RUBERNETES_K7_PREVIOUS_BIN_DIR and RUBERNETES_K7_TARGET_BIN_DIR"
    end

    entries = processes
    executables = entries.map { |process| process.fetch("executable") }.uniq
    older = release_info(previous, executables)
    newer = release_info(target, executables)
    unless Gem::Version.new(older.fetch("version")) < Gem::Version.new(newer.fetch("version")) &&
           newer.fetch("version") == "1.0.0"
      raise K7ClusterDriver::Unsupported, "K7 requires an earlier release and target release 1.0.0"
    end

    from, to = direction == :upgrade ? [older, newer] : [newer, older]
    unless entries.all? { |process| running_release?(process, from) }
      raise K7ClusterDriver::Unsupported, "#{direction} requires all cluster daemons running from release #{from.fetch("version")}"
    end

    # A rollback must read a write acknowledged by the newer artifact. Both
    # operations keep the same config, Raft data directories and node ledgers.
    with_checkpoint do |checkpoint|
      rolling_replace!(entries, to, workers_first: direction == :rollback)
      verify_checkpoint!(checkpoint)
      raise "not all components switched to #{to.fetch("version")}" unless entries.all? { |process| running_release?(process, to) }

      update_descriptor! { |descriptor| descriptor["bin_dir"] = to.fetch("bin_dir") }
      {"from_version" => from.fetch("version"), "to_version" => to.fetch("version"),
       "from_binaries" => from.fetch("sha256"), "to_binaries" => to.fetch("sha256"),
       "checkpoint_uid" => checkpoint.fetch("uid"), "checkpoint_revision" => checkpoint.fetch("resource_version")}
    end
  end

  def release_info(directory, executables)
    directory = File.realpath(directory)
    versions = executables.map do |executable|
      path = File.join(directory, executable)
      raise K7ClusterDriver::Unsupported, "release directory is missing executable #{path}" unless File.file?(path) && File.executable?(path)

      out, _err, status = Open3.capture3(path, "--version", chdir: K7ClusterDriver::ROOT)
      version = out.strip.match(/\A#{Regexp.escape(executable)} (\S+)\z/)&.captures&.first
      raise K7ClusterDriver::Unsupported, "could not identify release version from #{path}" unless status.success? && version

      version
    end.uniq
    raise K7ClusterDriver::Unsupported, "mixed versions in #{directory}: #{versions.join(", ")}" unless versions.one?

    {"bin_dir" => directory, "version" => versions.first,
     "sha256" => executables.to_h { |executable| [executable, Digest::SHA256.file(File.join(directory, executable)).hexdigest] }}
  rescue Errno::ENOENT
    raise K7ClusterDriver::Unsupported, "release directory or interpreter unavailable: #{directory}"
  end

  def running_release?(process, release)
    pid = pid_of(process)
    return false unless pid

    binary = File.join(release.fetch("bin_dir"), process.fetch("executable"))
    return false unless File.binread("/proc/#{pid}/cmdline").split("\0").include?(binary)

    Digest::SHA256.file(binary).hexdigest == release.fetch("sha256").fetch(process.fetch("executable")) &&
      console(process, "Rubernetes::VERSION") == release.fetch("version").inspect
  rescue Errno::ENOENT, Errno::ECONNREFUSED
    false
  end

  def rolling_replace!(entries, release, workers_first:)
    commands = []
    servers, clients = entries.partition { |process| process.fetch("executable") == "rubernetes-apiserver" }
    workers, controllers = clients.partition { |process| process.fetch("name").start_with?("agent-", "proxy-") }
    ordered = workers_first ? workers + controllers.reverse + servers.reverse : servers + controllers + workers
    ordered.each do |process|
      binary = File.join(release.fetch("bin_dir"), process.fetch("executable"))
      since = Time.now.utc
      pid = capture_process!(process)
      commands << [process, process.fetch("_argv"), process.fetch("_env")]
      Process.kill("TERM", pid)
      wait_for_exit!(process, pid)
      process["_argv"] = [binary, "--config", process.fetch("config")]
      # A checkout's Bundler and Ruby include paths must not resolve an
      # installed artifact's library back to the current sources.
      start!(process)
      wait_for_component!(process, since)
      wait_until("#{process.fetch("name")} serving release #{release.fetch("version")}", 30) do
        running_release?(process, release)
      end
    end
  rescue StandardError
    commands.reverse_each { |process, argv, env| restore_process!(process, argv, env) }
    raise
  end

  def restore_process!(process, argv, env)
    pid = pid_of(process)
    return if pid && File.binread("/proc/#{pid}/cmdline").split("\0") == argv

    stop!(process, signal: "TERM") if pid
    since = Time.now.utc
    process["_argv"] = argv
    process["_env"] = env
    start!(process)
    wait_for_component!(process, since)
  rescue StandardError => error
    warn "could not restore #{process.fetch("name")}: #{error.message}"
  end
end
