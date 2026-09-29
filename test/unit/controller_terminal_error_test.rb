# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A namespace on its way out answers every write with 403 "because it is being
# terminated", and then with 404 once it is gone.  Such a key can never
# succeed, and retrying it crowds out the keys that can: under a conformance
# run those retries alone grew the controller-manager work queue without bound
# (18 -> 405 keys in three minutes) while real work waited.
class ControllerTerminalErrorTest < Minitest::Test
  Manager = Rubernetes::Controller::Manager

  def manager
    @manager ||= Manager.allocate
  end

  def terminal?(message)
    manager.send(:terminal_reconcile_error?, RuntimeError.new(message))
  end

  def test_a_write_into_a_terminating_namespace_is_terminal
    assert(terminal?('Kubernetes API request POST /api/v1/namespaces/cronjob-4024/pods failed with HTTP 403: ' \
                     'unable to create new content in namespace cronjob-4024 because it is being terminated'))
  end

  def test_a_write_into_a_namespace_that_is_gone_is_terminal
    assert(terminal?('Kubernetes API request POST /api/v1/namespaces/watch-2370/serviceaccounts failed with ' \
                     'HTTP 404: namespaces "watch-2370" not found'))
  end

  def test_an_ordinary_failure_is_still_retried
    refute(terminal?("Kubernetes API request POST /api/v1/namespaces/dev/pods failed with HTTP 500: " \
                     "Internal error occurred"))
    refute(terminal?("connection refused"))
    refute(terminal?(""))
  end
end
