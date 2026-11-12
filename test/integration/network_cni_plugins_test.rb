# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"
require "open3"
require "securerandom"
require "tmpdir"

# The CNI runtime against the reference plugins (bridge, host-local,
# loopback) and a real network namespace: the Pod ends up with an address on
# eth0 and loses it again.
class NetworkCNIPluginsTest < Minitest::Test
  BIN = "/opt/cni/bin"

  def setup
    skip("needs root") unless Process.uid.zero?
    skip("needs the reference CNI plugins in #{BIN}") unless %w[bridge host-local loopback].all? { |name| File.executable?(File.join(BIN, name)) }

    @name = "rbn-cni-#{SecureRandom.hex(3)}"
    @bridge = "rbc#{SecureRandom.hex(3)}"
    @directory = Dir.mktmpdir
    system("ip", "netns", "add", @name, exception: true)
    File.write(File.join(@directory, "10-test.conflist"), JSON.generate(
      "cniVersion" => "1.0.0", "name" => @name,
      "plugins" => [{"type" => "bridge", "bridge" => @bridge, "isGateway" => true,
                     "ipam" => {"type" => "host-local", "dataDir" => File.join(@directory, "ipam"),
                                "ranges" => [[{"subnet" => "10.199.77.0/24"}]]}}]
    ))
    @cni = Rubernetes::Network::CNI.new(state_dir: File.join(@directory, "state"), conf_dir: @directory, bin_dirs: [BIN])
    @sandbox = {"sandbox_id" => @name, "netns" => {"path" => "/var/run/netns/#{@name}"}}
  end

  def teardown
    return unless @name

    system("ip", "netns", "delete", @name, err: File::NULL)
    system("ip", "link", "delete", @bridge, err: File::NULL)
    FileUtils.remove_entry(@directory)
  end

  def inside(*command)
    Open3.capture2("ip", "netns", "exec", @name, *command).first
  end

  def test_a_sandbox_gets_an_address_and_gives_it_back
    result = @cni.add(@sandbox, {"metadata" => {"namespace" => "shop", "name" => "web", "uid" => "u"}, "spec" => {"containers" => []}})
    address = result.fetch("ips").fetch(0)

    assert_match(/\A10\.199\.77\.\d+\z/, address)
    assert_match(%r{inet #{Regexp.escape(address)}/24}, inside("ip", "-4", "addr", "show", "dev", "eth0"))
    assert_match(/LOOPBACK,UP/, inside("ip", "link", "show", "dev", "lo"))
    assert_match(/\Aveth/, result.fetch("interface"))
    assert @cni.check(@sandbox)

    @cni.delete(@name)

    refute_match(/eth0/, inside("ip", "link"))
    assert_empty Dir[File.join(@directory, "ipam", @name, "10.199.77.*")], "the address is back in the pool"
  end
end
