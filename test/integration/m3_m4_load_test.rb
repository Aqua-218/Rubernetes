# frozen_string_literal: true

require "minitest/autorun"
require "rubernetes"

class M3M4LoadTest < Minitest::Test
  def test_public_m3_m4_surface_loads_from_root_require
    assert_equal 52, Rubernetes::Controller.default_registry.names.length
    assert_instance_of Rubernetes::Scheduler::Framework, Rubernetes::Scheduler.new
    assert defined?(Rubernetes::Network::IPAM)
    assert defined?(Rubernetes::Proxy::Proxy)
    assert defined?(Rubernetes::Volume::Manager)
  end
end
