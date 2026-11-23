# frozen_string_literal: true

require_relative "../test_helper"
require "net/http"
require "rubernetes/api"
require "rubernetes/node"
require "rubernetes/runtime/native"
require "tmpdir"

class PreviousContainerLogsTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  ProcessSupervisor = Rubernetes::Platform::Linux::ProcessSupervisor
  Node = Rubernetes::Node
  API = Rubernetes::API
  SIZE = 4096
  LOG_URL = "/api/v1/namespaces/default/pods/test/log"

  def setup
    @directory = Dir.mktmpdir("rbn-previous-logs-")
    @log_root = File.join(@directory, "logs")
    @runtime = Native.new(profile: :pure, process_adapter: ProcessSupervisor::ForkAdapter.new,
                          sandbox_root: File.join(@directory, "sandboxes"), log_root: @log_root,
                          journal_path: File.join(@directory, "journal"), max_log_bytes: SIZE, max_log_files: 2)
    @sandbox = @runtime.run_sandbox({}, id: "test-sandbox")
    @pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "test", "namespace" => "default"},
            "spec" => {"nodeName" => "node", "containers" => [{"name" => "app", "image" => "test"}]}}
    @entry = {name: "app"}
    @record = {pod: @pod, sandbox_id: @sandbox, state: "Running", containers: [@entry]}
    lifecycle = Struct.new(:records).new({"uid" => @record})
    service = Node::LogService.new(runtime: @runtime, trusted: true)
    @node = Node::StreamingServer.new(log_service: service, lifecycle: lifecycle, host: "127.0.0.1", port: 0).start
    endpoint = API::NodeEndpointResolver::Endpoint.new(URI("http://127.0.0.1:#{@node.port}"), read_timeout: 3)
    resolver = Struct.new(:endpoint) do
      def resolve(pod:)
        API::NodeEndpointResolver::PodScopedEndpoint.new(endpoint, pod)
      end
    end.new(endpoint)
    start_api(resolver)
  end

  def teardown
    @http&.stop
    @node&.stop
    @runtime&.remove_sandbox(@sandbox) if @sandbox
  ensure
    FileUtils.remove_entry(@directory) if @directory
  end

  def test_two_latest_attempts_are_readable_and_older_disk_is_reclaimed
    first = run_attempt("a")
    current(first)

    assert_equal "200", get_log.code
    missing = get_log("previous=true&follow=true")

    assert_equal "400", missing.code
    assert_equal 'previous terminated container "app" in pod "test" not found', JSON.parse(missing.body).fetch("message")

    second = run_attempt("b")
    @runtime.retire_container(first)
    current(second, previous: first)

    assert_equal "a" * (SIZE * 2), get_log("previous=true&follow=true").body
    assert_equal "b" * (SIZE * 2), get_log.body

    third = run_attempt("c")

    assert_equal SIZE * 12, allocated_log_bytes

    @runtime.retire_container(second, previous_id: first)
    current(third, previous: second)

    assert_equal "b" * (SIZE * 2), get_log("previous=true").body
    refute_path_exists File.join(@log_root, handle_id(first))
    assert_equal [handle_id(second), handle_id(third)].sort, Dir.children(@log_root).sort
    files = Dir.glob(File.join(@log_root, "*", "*.log*"))

    assert_equal 8, files.size
    assert(files.all? { |path| File.size(path) <= SIZE })
    assert_equal SIZE * 8, allocated_log_bytes

    # A new supervisor has no in-memory readers for the prior attempt.
    recovered_reader = ProcessSupervisor.new(process_adapter: ProcessSupervisor::ForkAdapter.new, log_directory: @log_root,
                                             max_log_bytes: SIZE, max_log_files: 2)

    assert_equal "b" * (SIZE * 2), recovered_reader.logs(handle_id(second), stream: :all)

    # Recovered sandboxes have no in-memory ids for retired containers.
    @runtime.sandbox(@sandbox).stub(:container_ids_ever, []) { @runtime.remove_sandbox(@sandbox) }

    assert_empty Dir.children(@log_root)
    assert_equal 0, allocated_log_bytes
  end

  private

  def start_api(node_resolver)
    api = API::Server.new(node_resolver: node_resolver, trusted_subresources: true, identity_resolver: ->(_request) { "test-user" })
    @http = Rubernetes::Transport::HTTPServer.new(api, port: 0)
    @http.start
    response = Net::HTTP.start("127.0.0.1", @http.port, open_timeout: 3, read_timeout: 3) do |client|
      client.post("/api/v1/namespaces/default/pods", JSON.generate(@pod), {"Content-Type" => "application/json"})
    end

    assert_equal "201", response.code, response.body
  end

  def run_attempt(character)
    command = [RbConfig.ruby, "-e", "STDOUT.write(ARGV.fetch(0) * #{SIZE * 3})", character]
    container = @runtime.create_container(@sandbox, {"name" => "app", "command" => command})
    @runtime.start_container(container)

    assert_equal 0, @runtime.wait_container(container, timeout: 5).fetch("exitCode")
    container.id
  end

  def current(id, previous: nil)
    @entry[:id] = id
    @entry[:started] = true
    @entry[:status] = {"lastState" => {"terminated" => {"containerID" => previous}}} if previous
  end

  def get_log(query = nil)
    path = [LOG_URL, query].compact.join("?")
    Net::HTTP.start("127.0.0.1", @http.port, open_timeout: 3, read_timeout: 3) { |client| client.get(path) }
  end

  def handle_id(id) = "process-#{@sandbox}-#{id}"

  def allocated_log_bytes
    Dir.glob(File.join(@log_root, "*", "*.log*")).sum { |path| File.stat(path).blocks * 512 }
  end
end
