# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class PodDisruptionBudgetAdmissionTest < Minitest::Test
  PDBS = "/apis/policy/v1/namespaces/default/poddisruptionbudgets"
  ZERO_STATUS = {"disruptionsAllowed" => 0, "currentHealthy" => 0, "desiredHealthy" => 0, "expectedPods" => 0}.freeze

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @store = Rubernetes::API::MemoryStore.new
    @server = Rubernetes::API::Server.new(registry: registry, store: @store)
  end

  def test_spec_validation_orders_threshold_selector_and_policy_errors
    spec = {"minAvailable" => -1, "maxUnavailable" => "101%", "selector" => {"matchExpressions" => [{"key" => "app", "operator" => "In"}]},
            "unhealthyPodEvictionPolicy" => "Other"}
    result = create(spec)
    expected = [
      ["spec", "Invalid value: {\"MinAvailable\":-1,\"Selector\":{\"matchExpressions\":[{\"key\":\"app\",\"operator\":\"In\"}]}," \
               "\"MaxUnavailable\":\"101%\",\"UnhealthyPodEvictionPolicy\":\"Other\"}: minAvailable and maxUnavailable cannot be both set"],
      ["spec.minAvailable", "Invalid value: -1: must be greater than or equal to 0"],
      ["spec.maxUnavailable", 'Invalid value: "101%": must not be greater than 100%'],
      ["spec.selector.matchExpressions[0].values", "Required value: must be specified when `operator` is 'In' or 'NotIn'"],
      ["spec.unhealthyPodEvictionPolicy", 'Unsupported value: "Other": supported values: "AlwaysAllow", "IfHealthyBudget"']
    ]

    assert_equal(expected, causes(result).map { |entry| entry.values_at("field", "message") })
    assert_equal 404, request("GET", "#{PDBS}/budget").status
  end

  def test_main_create_and_updates_ignore_status_and_keep_typed_zero_fields
    input = budget({"minAvailable" => 1}).merge("status" => {"disruptionsAllowed" => -5})
    result = request("POST", PDBS, input)

    assert_equal 201, result.status
    assert_equal ZERO_STATUS, result.body.fetch("status")
    status_path = "#{PDBS}/budget/status"
    update = request("PATCH", status_path, {"status" => {"disruptionsAllowed" => 2}})

    assert_equal 200, update.status
    data = {"spec" => {"minAvailable" => "20%"}, "status" => {"disruptionsAllowed" => -6}}
    updated = request("PUT", "#{PDBS}/budget", update.body.merge(data))

    assert_equal 200, updated.status
    assert_equal ZERO_STATUS.merge("disruptionsAllowed" => 2), updated.body.fetch("status")
    updated = request("PATCH", "#{PDBS}/budget", {"spec" => {"minAvailable" => 3}, "status" => {"currentHealthy" => -5}})

    assert_equal 200, updated.status
    assert_equal ZERO_STATUS.merge("disruptionsAllowed" => 2), updated.body.fetch("status")
  end

  def test_status_validation_orders_conditions_then_counters_and_rejects_atomically
    current = create({"minAvailable" => 1}).body
    status = {"conditions" => [{"type" => "DisruptionAllowed", "status" => "Maybe", "observedGeneration" => -1}],
              "expectedPods" => -4, "desiredHealthy" => -3, "currentHealthy" => -2, "disruptionsAllowed" => -1}
    changes = {"status" => status, "spec" => {"maxUnavailable" => -1}}
    expected = %w[status.conditions[0].status status.conditions[0].observedGeneration status.conditions[0].lastTransitionTime
                  status.conditions[0].reason status.disruptionsAllowed status.currentHealthy status.desiredHealthy status.expectedPods]
    %w[PUT PATCH].each do |method|
      body = method == "PUT" ? current.merge(changes) : changes
      response = request(method, "#{PDBS}/budget/status", body)

      assert_equal(expected, causes(response).map { |entry| entry.fetch("field") })
      assert_equal current, request("GET", "#{PDBS}/budget").body
    end
  end

  def test_status_dry_run_and_live_updates_keep_the_legacy_spec
    legacy_spec = {"minAvailable" => 1, "maxUnavailable" => 1}
    @store.create("registry/policy/v1/poddisruptionbudgets/default/budget", budget(legacy_spec).merge("status" => ZERO_STATUS))
    current = request("GET", "#{PDBS}/budget").body
    patch = {"spec" => {"minAvailable" => "50%"}, "status" => {"currentHealthy" => 3}}
    preview = request("PATCH", "#{PDBS}/budget/status?dryRun=All", patch)

    assert_equal 200, preview.status
    assert_equal legacy_spec, preview.body.fetch("spec")
    assert_equal current, request("GET", "#{PDBS}/budget").body
    live = request("PATCH", "#{PDBS}/budget/status", patch)

    assert_equal 200, live.status
    assert_equal legacy_spec, live.body.fetch("spec")
    assert_equal ZERO_STATUS.merge("currentHealthy" => 3), live.body.fetch("status")
    assert_equal live.body, request("GET", "#{PDBS}/budget").body
  end

  def test_threshold_integer_overflow_is_rejected_during_decode
    result = create({"minAvailable" => 2_147_483_648})

    assert_equal 400, result.status
    assert_match(/json: cannot unmarshal number 2147483648 into Go struct field PodDisruptionBudgetSpec.spec.minAvailable of type int32/,
                 result.body.fetch("message"))
  end

  def test_status_patch_wire_errors_preserve_the_stored_object
    current = create({"minAvailable" => 1}).body
    response = request("PATCH", "#{PDBS}/budget/status", {"status" => {"expectedPods" => 2_147_483_648}})

    assert_equal [
      {"field" => "patch", "reason" => "FieldValueInvalid",
       "message" => "json: cannot unmarshal number 2147483648 into Go struct field PodDisruptionBudgetStatus.status.expectedPods of type int32"}
    ], causes(response)
    assert_equal current, request("GET", "#{PDBS}/budget").body
  end

  private

  def budget(spec)
    {"apiVersion" => "policy/v1", "kind" => "PodDisruptionBudget", "metadata" => {"name" => "budget"}, "spec" => spec}
  end

  def create(spec) = request("POST", PDBS, budget(spec))

  def request(method, path, object = nil)
    media = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    request = Rubernetes::API::Request.new(method: method, path: path, headers: {"content-type" => media},
                                           body: object && JSON.generate(object), identity: {"username" => "admin", "groups" => ["system:masters"]})
    @server.call(request)
  end

  def causes(response)
    assert_equal 422, response.status, response.body.inspect
    response.body.fetch("details").fetch("causes")
  end
end
