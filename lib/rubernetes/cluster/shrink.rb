# frozen_string_literal: true

module Rubernetes
  module Cluster
    # `scale --controls N` with N below the current count: takes the newest
    # control nodes out of the running cluster.  The datastore loses them as
    # voters first (so it never waits for a node that is gone), then every
    # component that talked to one of them is pointed at a node that stays.
    module Shrink
      private

      def shrink(descriptor, current, controls)
        raise Error, "a cluster keeps at least one control node" if controls < 1

        kept = current.first(controls)
        removed = current.drop(controls)
        documents = current.to_h { |id| [id, YAML.safe_load_file(config_path("apiserver-#{id}"))] }
        raise Error, "#{root} does not run the raft datastore" unless documents.values.first.dig(*DATASTORE_PATH, "type") == "raft"

        hand_over_leadership(kept, removed)
        leave_datastore!(kept, removed)
        moved = repoint_clients(documents, kept, removed)
        retire_control_nodes(descriptor, removed)
        rewrite_kept_configs(documents, kept)
        restart_clients(descriptor, moved)

        descriptor["scaled_at"] = Time.now.utc.iso8601
        File.write(descriptor_path, JSON.pretty_generate(descriptor))
        descriptor
      end

      DATASTORE_PATH = %w[processes rubernetes-apiserver datastore].freeze

      # A leader that is about to be removed gives the lead to a node that
      # stays, so the membership change is proposed by a node that survives it.
      def hand_over_leadership(kept, removed)
        leader = removed.find { |id| console_eval("apiserver-#{id}", "raft.leader?")["result"] == "true" }
        return unless leader

        answer = console_eval("apiserver-#{leader}", "raft.transfer_leadership(#{kept.first.inspect}); :done")
        raise Error, "control node #{leader} could not hand over the datastore's lead (#{answer["error"]})" unless answer["result"] == ":done"

        await!("a remaining control node to lead the datastore") do
          kept.any? { |id| console_eval("apiserver-#{id}", "raft.leader?")["result"] == "true" }
        end
      end

      def leave_datastore!(kept, removed)
        code = "service.reconfigure_datastore(voters: #{kept.inspect}, removed: #{removed.inspect}); :done"
        refusals = []
        await!("the datastore to drop #{removed.join(", ")}") do
          refusals = kept.map do |id|
            answer = console_eval("apiserver-#{id}", code)
            break nil if answer["result"] == ":done"

            "#{id}: #{answer["error"]}"
          end
          refusals.nil?
        end
      rescue Error => error
        raise Error, "#{error.message} (#{Array(refusals).join("; ")})"
      end

      # Every kubeconfig under the root that names a removed node's API
      # endpoint now names a remaining one.  Returns the files changed.
      def repoint_clients(documents, kept, removed)
        endpoint = ->(id) { "https://127.0.0.1:#{documents.fetch(id).dig("processes", "rubernetes-apiserver", "port")}" }
        targets = kept.map(&endpoint).cycle
        replacements = removed.to_h { |id| [endpoint.call(id), targets.next] }
        client_files.select do |path|
          text = File.binread(path)
          rewritten = replacements.reduce(text) { |result, (from, to)| result.gsub(/#{Regexp.escape(from)}(?!\d)/, to) }
          next false if rewritten == text

          File.binwrite(path, rewritten)
          true
        end
      end

      def client_files
        patterns = [File.join(root, "*kubeconfig*"), File.join(root, "config", "*.yml"), File.join(root, "runtime", "**", "*.conf"),
                    File.join(root, "pki", "**", "*kubeconfig*")]
        Dir.glob(patterns).select { |path| File.file?(path) }.reject { |path| File.basename(path).start_with?("apiserver-") }.uniq
      end

      def retire_control_nodes(descriptor, removed)
        names = removed.map { |id| "apiserver-#{id}" }
        gone, rest = descriptor.fetch("processes").partition { |process| names.include?(process.fetch("name")) }
        gone.each { |process| terminate(process.fetch("pid"), process.fetch("name"), process.fetch("config")) }
        descriptor["processes"] = rest
        # kubeconfig-<id> stays: components were given it by name, and it now
        # names a node that remains.
        removed.each do |id|
          FileUtils.rm_rf([File.join(root, "data", id), File.join(root, "raft-pki", id), config_path("apiserver-#{id}"),
                           File.join(root, "run", "apiserver-#{id}.sock"),
                           File.join(root, "pids", "apiserver-#{id}.pid")])
        end
      end

      def rewrite_kept_configs(documents, kept)
        addresses = kept.to_h { |id| [id, raft_address(documents.fetch(id))] }
        kept.each do |id|
          document = documents.fetch(id)
          port = document.dig("processes", "rubernetes-apiserver", "port")
          write_config("apiserver-#{id}", control_node_config(document, id, addresses, voters: kept, port: port))
        end
      end

      # A component reads its kubeconfig once, at start: the ones whose
      # kubeconfig moved start again, control loops before the nodes.
      def restart_clients(descriptor, moved)
        return if moved.empty?

        processes = descriptor.fetch("processes")
        affected = processes.select { |process| client_of?(process, moved) }
        affected.reverse_each { |process| terminate(process.fetch("pid"), process.fetch("name"), process.fetch("config")) }
        since = Time.now.utc
        affected.each do |process|
          processes[processes.index(process)] = spawn_process(process.fetch("name"), process.fetch("executable"), process.fetch("config"))
        end
        agents = processes.count { |process| process.fetch("executable") == "rubernetes-agent" }
        restarted = affected.count { |process| process.fetch("executable") == "rubernetes-agent" }
        await!("#{agents} Ready nodes") { ready_nodes(kubeconfig, since: since) >= restarted && ready_nodes(kubeconfig) >= agents }
        raise_on_dead!(processes, "scale")
      end

      def client_of?(process, moved)
        return false if process.fetch("executable") == "rubernetes-apiserver"

        config = process.fetch("config")
        moved.include?(config) || moved.any? { |path| File.binread(config).include?(path) }
      end
    end
  end
end
