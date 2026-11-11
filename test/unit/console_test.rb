# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/console/cli"
require "rubernetes/console/server"
require "stringio"
require "tmpdir"

# A Ruby prompt inside a running component: what is typed is evaluated
# against the live objects, by the owner of the socket only.
class ConsoleTest < Minitest::Test
  C = Rubernetes::Console

  # Stands in for a component's service object.
  class Service
    attr_reader :framework

    def initialize
      @framework = Struct.new(:plugins, :queue).new([Struct.new(:name).new("NodeName")], [])
      @secret_state = {"pods" => 3}
    end

    def work(pod, times: 1) = "#{pod["metadata"]["name"]}x#{times}"
  end

  def setup
    @directory = Dir.mktmpdir
    @root = File.join(@directory, "cluster")
    @service = Service.new
    @server = C::Server.new(path: File.join(@root, "run", "scheduler.sock"), process_name: "rubernetes-scheduler", service: @service).start
  end

  def teardown
    @server.stop
    FileUtils.remove_entry(@directory)
  end

  def rubectl(command, *arguments, input: "")
    stdout = StringIO.new
    stderr = StringIO.new
    status = C::CLI.new(stdout: stdout, stderr: stderr, stdin: StringIO.new(input)).run(command, [*arguments, "--root", @root])
    [status, stdout.string, stderr.string]
  end

  def evaluate(code) = rubectl("console", "scheduler", "-e", code)

  def test_code_is_evaluated_against_the_live_service
    assert_equal [0, "=> [\"NodeName\"]\n"], evaluate("plugins").first(2)
    assert_equal [0, "=> {\"pods\" => 3}\n"], evaluate("ivar(service, :secret_state)").first(2)

    evaluate("ivar(service, :secret_state)[\"pods\"] = 4")

    assert_equal 4, @service.instance_variable_get(:@secret_state).fetch("pods"), "the prompt reaches the process's own objects"
  end

  def test_what_is_printed_comes_back_to_the_session_not_into_the_components_output
    status, stdout, = evaluate('puts "seen"; p :also; 7')

    assert_equal 0, status
    assert_equal "seen\n:also\n=> 7\n", stdout
  end

  def test_an_error_is_reported_and_the_component_goes_on
    status, stdout, = evaluate("no_such_thing")

    assert_equal 1, status
    assert_match(/\ANameError: undefined local variable or method 'no_such_thing'/, stdout)
    assert_equal 0, evaluate("1 + 1").first
    assert_match(/\ASyntaxError/, evaluate("1 +* 2")[1])
  end

  # The prompt is inside the component: Kernel#exit! there would take the
  # scheduler down with the session.
  def test_leaving_the_ruby_way_does_not_stop_the_component
    %w[exit exit! abort].each { |word| assert_match(/\ARuntimeError: #{Regexp.escape(word)} would stop the component/, evaluate(word)[1]) }
    assert_equal 0, evaluate("1").first
  end

  def test_a_session_keeps_its_variables_and_reads_blocks_over_several_lines
    status, stdout, = rubectl("console", "scheduler", input: <<~INPUT)
      names = plugins.map do |name|
        name.downcase
      end
      names.first
      1 +* 2
      exit
      never_reached
    INPUT

    assert_equal 0, status
    lines = stdout.lines

    assert_match(/\Arubernetes-scheduler \(pid #{Process.pid}, Ruby #{RUBY_VERSION}\)/, lines.fetch(0))
    assert_equal "=> [\"nodename\"]\n", lines.fetch(1)
    assert_equal "=> \"nodename\"\n", lines.fetch(2)
    assert_match(/\ASyntaxError/, lines.fetch(3))
    refute_includes stdout, "never_reached"
  end

  def test_a_large_object_is_shown_as_what_it_holds
    assert_equal "=> #<ConsoleTest::Service @framework @secret_state>\n", evaluate("service")[1]
    assert_equal "=> [:@framework, :@secret_state]\n", evaluate("ivars(service)")[1]
    assert_match(/\.\.\. \(30 more\)\]\n\z/, evaluate("(1..50).to_a")[1])
    assert_match(/\(5000 characters\)\n\z/, evaluate('"x" * 5000')[1])
  end

  def test_help_lists_the_helpers_of_the_component
    _status, stdout, = evaluate("help")

    %w[service ivars threads memory framework queue plugins why].each { |name| assert_match(/^  #{name} /, stdout) }
  end

  def test_a_process_is_named_by_a_unique_beginning
    assert_equal 0, rubectl("console", "sched", "-e", "1").first
    status, _stdout, stderr = rubectl("console", "agent", "-e", "1")

    assert_equal 1, status
    assert_match(/"agent" names no process; there are scheduler/, stderr)
    assert_equal 64, rubectl("console").first
  end

  def test_the_calls_of_a_method_are_reported_while_it_is_watched
    caller = Thread.new do
      20.times do |index|
        sleep 0.05
        @service.work({"kind" => "Pod", "metadata" => {"name" => "p#{index}", "namespace" => "shop"}}, times: index)
      end
    end
    status, stdout, = rubectl("trace", "scheduler", "ConsoleTest::Service#work", "--seconds", "5", "--limit", "2")
    caller.join

    assert_equal 0, status
    assert_match(%r{ms  pod=#<Pod shop/p\d+> times=\d+  => "p\d+x\d+"$}, stdout)
    assert_equal "2 calls\n", stdout.lines.last
  end

  def test_a_method_that_does_not_exist_cannot_be_traced
    status, _stdout, stderr = rubectl("trace", "scheduler", "ConsoleTest::Service#nothing")

    assert_equal 1, status
    assert_match(/undefined method 'nothing'/, stderr)
  end

  # The socket is the whole of the access control.
  def test_the_socket_is_its_owners_alone
    path = File.join(@root, "run", "scheduler.sock")

    assert_equal 0o600, File.stat(path).mode & 0o777
    assert_equal 0o700, File.stat(File.dirname(path)).mode & 0o777

    @server.stop

    refute_path_exists path
  end

  def test_a_path_the_kernel_would_cut_is_refused
    long = File.join(@directory, "x" * 100, "scheduler.sock")

    assert_raises(ArgumentError) { C::Server.new(path: long, process_name: "rubernetes-scheduler", service: @service).start }
  end
end
