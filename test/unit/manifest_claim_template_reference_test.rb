# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/manifest/builder"

class ManifestClaimTemplateReferenceTest < Minitest::Test
  M = Rubernetes::Manifest
  ROOT = File.expand_path("../..", __dir__)

  def self.schema_data
    @schema_data ||= [JSON.parse(File.binread(File.join(ROOT, "generated/schema/registry.json")), max_nesting: 512),
                      JSON.parse(File.binread(File.join(ROOT, "generated/openapi/v2.json")), max_nesting: 512).fetch("definitions")]
  end

  def test_generated_claim_reference_is_shared_by_init_and_application_containers
    objects = build(<<~RUBY)
      in_namespace "preview" do
        stateful_set "db" do
          service_name "db"
          data = volume_claim_template "data" do
            access_modes [:ReadWriteOnce]
            resources { requests storage: "1024Mi" }
          end
          disk = volume_claim_template "disk" do
            access_modes ["ReadWriteOnce"]
            volume_mode "Block"
            resources requests: {storage: "2Gi"}
          end
          init_container("prepare", image: "busybox") { mount data, at: "/data", read_only: true }
          container "database", image: "postgres:17" do
            mount data, at: "/var/lib/postgresql/data"
            device disk, at: "/dev/cache"
          end
        end
      end
    RUBY
    spec = objects.first.fetch("spec")
    pod = spec.dig("template", "spec")

    assert_equal(["StatefulSet"], objects.map { |object| object.fetch("kind") })
    assert_equal "preview", objects.first.dig("metadata", "namespace")
    assert_equal "1Gi", spec.dig("volumeClaimTemplates", 0, "spec", "resources", "requests", "storage")
    assert_equal ["ReadWriteOnce"], spec.dig("volumeClaimTemplates", 0, "spec", "accessModes")
    assert_equal({"name" => "data", "mountPath" => "/data", "readOnly" => true}, pod.dig("initContainers", 0, "volumeMounts", 0))
    assert_equal "data", pod.dig("containers", 0, "volumeMounts", 0, "name")
    assert_equal "disk", pod.dig("containers", 0, "volumeDevices", 0, "name")
    refute pod.key?("volumes")
  end

  def test_a_reference_belongs_only_to_its_own_stateful_set
    source = <<~RUBY
      claim = nil
      stateful_set "db", namespace: "preview" do
        claim = volume_claim_template "data"
      end
      stateful_set "worker", namespace: "preview" do
        container("worker", image: "busybox") { mount claim, at: "/data" }
      end
    RUBY

    assert_equal 'app.rb:6: claim template "data" belongs to a different StatefulSet', error_of(source)
    deployment = source.sub('stateful_set "worker", namespace: "preview"', 'deployment "worker", namespace: "prod"')

    assert_equal 'app.rb:6: claim template "data" belongs to a different StatefulSet', error_of(deployment)
  end

  def test_reused_template_claim_reports_collisions_and_wrong_mode_at_the_mount
    source = <<~RUBY
      stateful_set "db" do
        claim = volume_claim_template "data"
        container("db", image: "busybox") { mount claim, at: "/data" }
        volume "data"
      end
    RUBY

    assert_equal 'app.rb:3: StatefulSet claim template "data" conflicts with another volume declaration', error_of(source)
    overridden = source.sub('volume "data"', 'volume_claim_templates [{metadata: {name: "data"}}]')

    assert_equal 'app.rb:3: StatefulSet claim template "data" no longer refers to its declaration', error_of(overridden)
    block = source.sub('volume_claim_template "data"', 'volume_claim_template("data") { volume_mode "Block" }').sub('  volume "data"', "")

    assert_equal "app.rb:3: volumeClaimTemplates/data has volumeMode Block; use device", error_of(block)
  end

  def test_writer_validates_template_namespace_modes_quantity_and_duplicate_name
    invalid_fields = {
      'volume_claim_template "data", namespace: "prod"' => /must inherit the StatefulSet namespace "preview"/,
      'volume_claim_template("data") { access_modes ["ReadWriteOncePod", "ReadOnlyMany"] }' => /cannot combine ReadWriteOncePod/,
      'volume_claim_template("data") { access_modes ["ReadWriteOnc"] }' => /accessModes must use/,
      'volume_claim_template("data") { volume_mode "Blocks" }' => /volumeMode must be Block or Filesystem/,
      'volume_claim_template("data") { resources { requests storage: "fast" } }' => /requests\.storage has invalid quantity/,
      'volume_claim_template("data") { resources { requests storage: "0Gi" } }' => /requests\.storage must be greater than zero/,
      '2.times { volume_claim_template "data" }' => /claim template "data" was declared more than once/
    }
    invalid_fields.each do |declaration, reason|
      message = error_of("stateful_set \"db\", namespace: \"preview\" do\n  #{declaration}\nend")

      assert_match(/\Aapp\.rb:2: /, message)
      assert_match reason, message
    end
  end

  private

  def build(source)
    registry, definitions = self.class.schema_data
    M::Builder.new(registry: registry, definitions: definitions).evaluate(source, "app.rb")
  end

  def error_of(source) = assert_raises(M::Error) { build(source) }.message
end
