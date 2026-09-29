# frozen_string_literal: true

# The admission context the security admission plugin tests share.  Kept out
# of the test files: a test file that requires another one loads it twice
# under the Minitest inventory (which loads every test file itself), and the
# second load redefines its constants.
class SecurityAdmissionFakeContext
  attr_reader :objects, :clock, :feature_gates
  attr_accessor :authorizer

  def initialize
    @objects = Hash.new { |hash, key| hash[key] = {} }
    @clock = -> { Time.now.utc }
    @feature_gates = {}
  end

  def put(resource, namespace, name, object, group: "")
    @objects[[group, resource, namespace.to_s]][name] = object
  end

  def get(resource, namespace, name, group: "", version: "v1")
    @objects[[group, resource, namespace.to_s]][name]
  end

  def list(resource, namespace = nil, group: "", version: "v1")
    return @objects.select { |(g, r, _), _| g == group && r == resource }.values.flat_map(&:values) if namespace.nil?

    @objects[[group, resource, namespace.to_s]].values
  end

  def update(resource, namespace, name, object, resource_version:, group: "", version: "v1")
    put(resource, namespace, name, object, group: group)
  end

  def namespace(name) = get("namespaces", nil, name)
  def feature_enabled?(gate) = @feature_gates.fetch(gate, false)
end
