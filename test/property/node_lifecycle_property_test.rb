# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeLifecyclePropertyTest < Minitest::Test
  SEEDS = [0xA11CE, 0xBACC0, 0xC0FFEE].freeze

  def test_backoff_never_decreases_before_the_ten_minute_reset
    SEEDS.each do |seed|
      random = Random.new(seed)
      clock = 0
      manager = Rubernetes::Node::RestartManager.new(clock: -> { clock }, sleeper: ->(_seconds) {})
      observed = []
      12.times do
        manager.record_start("container-#{seed}", at: clock)
        clock += random.rand(0..30)
        observed << manager.record_exit("container-#{seed}", policy: "Always", exit_code: 1, at: clock).delay_seconds
      end
      observed.each_cons(2) { |previous, current| assert_operator current, :>=, previous, "seed=#{seed}" }
      assert_equal 300, observed.last, "seed=#{seed}"

      manager.record_start("container-#{seed}", at: clock)
      clock += 600
      reset = manager.record_exit("container-#{seed}", policy: "Always", exit_code: 1, at: clock)
      # After the reset the next failure is a first failure again, which
      # kubelet restarts at once (doBackOff: no backoff entry yet).
      assert_equal 0, reset.delay_seconds, "seed=#{seed}"
    end
  end
end
