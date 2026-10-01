# frozen_string_literal: true

require "json"
require "rbconfig"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/credential_providers"
require "rubernetes/node/image_credentials"
require "rubernetes/bootstrap"
require "rubernetes/observability/metrics"
require "digest"

# Kubelet image credential provider plugins (pkg/credentialprovider/plugin,
# v1.36.2) with KubeletServiceAccountTokenForCredentialProviders.
class CredentialProvidersTest < Minitest::Test
  CP = Rubernetes::Node::CredentialProviders

  # Answers every request with +response+ and appends the request to a log.
  def write_plugin(dir, name, response)
    path = File.join(dir, name)
    File.write(path, <<~RUBY)
      #!#{RbConfig.ruby}
      require "json"
      request = JSON.parse($stdin.read)
      File.open(#{File.join(dir, "#{name}.log").inspect}, "a") { |file| file.puts(JSON.generate(request.merge("env" => ENV["EXTRA"]))) }
      puts JSON.generate(#{response.inspect})
    RUBY
    File.chmod(0o755, path)
    path
  end

  def config(dir, providers, file: "config.yaml")
    path = File.join(dir, file)
    File.write(path,
               JSON.generate({"apiVersion" => "kubelet.config.k8s.io/v1", "kind" => "CredentialProviderConfig", "providers" => providers}))
    path
  end

  def provider(name, **overrides)
    {"name" => name, "apiVersion" => "credentialprovider.kubelet.k8s.io/v1", "matchImages" => ["*.registry.example", "registry.example"],
     "defaultCacheDuration" => "10m", "env" => [{"name" => "EXTRA", "value" => "yes"}]}.merge(overrides.transform_keys(&:to_s))
  end

  def response(auth, key: "Registry", duration: nil)
    body = {"apiVersion" => "credentialprovider.kubelet.k8s.io/v1", "kind" => "CredentialProviderResponse", "cacheKeyType" => key,
            "auth" => auth}
    body["cacheDuration"] = duration if duration
    body
  end

  def log(dir, name)
    File.exist?(File.join(dir, "#{name}.log")) ? File.readlines(File.join(dir, "#{name}.log")).map { |line| JSON.parse(line) } : []
  end

  def test_a_matching_image_execs_the_plugin_and_caches_its_answer
    Dir.mktmpdir do |dir|
      write_plugin(dir, "ecr", response({"registry.example" => {"username" => "u", "password" => "p"}}))
      providers = CP.load(config_path: config(dir, [provider("ecr")]), bin_dir: dir)
      credentials = providers.lookup("registry.example/team/app:1")

      assert_equal([["registry.example", "u", "p", nil]], credentials.map { |c| [c.registry, c.username, c.password, c.service_account] })
      assert_equal [{"kind" => "CredentialProviderRequest", "apiVersion" => "credentialprovider.kubelet.k8s.io/v1",
                     "image" => "registry.example/team/app:1", "env" => "yes"}], log(dir, "ecr")
      providers.lookup("registry.example/other:2")

      assert_equal 1, log(dir, "ecr").length, "the Registry cache key served the second image"
      assert_empty providers.lookup("docker.io/library/busybox")
      assert_equal 1, log(dir, "ecr").length, "an unmatched image never runs the plugin"
    end
  end

  # pkg/credentialprovider/plugin/metrics.go: the config hash info metric
  # (sha256 over length-prefixed files), plugin durations and errors.
  def test_metrics
    Dir.mktmpdir do |dir|
      write_plugin(dir, "ecr", response({"registry.example" => {"username" => "u", "password" => "p"}}))
      File.write(File.join(dir, "broken"), "#!/bin/sh\nexit 3\n")
      File.chmod(0o755, File.join(dir, "broken"))
      path = config(dir, [provider("ecr"), provider("broken", matchImages: ["other.example"])])
      providers = CP.load(config_path: path, bin_dir: dir)
      registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
      providers.metrics = registry
      providers.lookup("registry.example/app:1")

      assert_empty providers.lookup("other.example/app:1"), "a failing plugin gives no credentials"
      data = File.binread(path)
      expected = "sha256:#{Digest::SHA256.hexdigest([data.bytesize].pack("Q>") + data)}"
      text = registry.render

      assert_includes text, %(kubelet_credential_provider_config_info{hash="#{expected}"} 1)
      assert_includes text, %(kubelet_credential_provider_plugin_duration_count{plugin_name="ecr"} 1)
      assert_includes text, %(kubelet_credential_provider_plugin_errors_total{plugin_name="broken"} 1)
    end
  end

  def test_zero_cache_duration_runs_the_plugin_every_time
    Dir.mktmpdir do |dir|
      write_plugin(dir, "p", response({"registry.example" => {"username" => "u", "password" => "p"}}, duration: "0s"))
      providers = CP.load(config_path: config(dir, [provider("p")]), bin_dir: dir)
      2.times { providers.lookup("registry.example/app") }

      assert_equal 2, log(dir, "p").length
    end
  end

  def test_service_account_tokens_annotations_and_attribution
    Dir.mktmpdir do |dir|
      write_plugin(dir, "wi", response({"registry.example" => {"username" => "oauth", "password" => "from-token"}}))
      attributes = {"serviceAccountTokenAudience" => "registry.example", "requireServiceAccount" => true, "cacheType" => "ServiceAccount",
                    "requiredServiceAccountAnnotationKeys" => ["example.com/role"], "optionalServiceAccountAnnotationKeys" => ["example.com/extra"]}
      tokens = []
      requester = lambda do |namespace, name, audience:, service_account_uid:, pod_name:, pod_uid:|
        tokens << [namespace, name, audience, service_account_uid, pod_name, pod_uid]
        "token-#{tokens.length}"
      end
      accounts = {"ns/builder" => {"metadata" => {"uid" => "sa-uid", "annotations" => {"example.com/role" => "pull"}}},
                  "ns/plain" => {"metadata" => {"uid" => "sa-2", "annotations" => {}}}}
      providers = CP.load(config_path: config(dir, [provider("wi", tokenAttributes: attributes)]), bin_dir: dir,
                          token_requester: requester, service_account_reader: ->(ns, name) { accounts["#{ns}/#{name}"] })
      pod = {"metadata" => {"namespace" => "ns", "name" => "p", "uid" => "pod-uid"}, "spec" => {"serviceAccountName" => "builder"}}
      credential = providers.lookup("registry.example/app", pod: pod).first

      assert_equal({uid: "sa-uid", namespace: "ns", name: "builder"}, credential.service_account)
      assert_equal [["ns", "builder", "registry.example", "sa-uid", "p", "pod-uid"]], tokens
      request = log(dir, "wi").first

      assert_equal "token-1", request["serviceAccountToken"]
      assert_equal({"example.com/role" => "pull"}, request["serviceAccountAnnotations"])
      # A missing required annotation, or no ServiceAccount at all: nothing.
      assert_empty providers.lookup("registry.example/app", pod: pod.merge("spec" => {"serviceAccountName" => "plain"}))
      assert_empty providers.lookup("registry.example/app", pod: pod.merge("spec" => {}))
      assert_empty providers.lookup("registry.example/app")
    end
  end

  def test_the_token_returned_as_password_is_refused_unless_cached_per_token
    Dir.mktmpdir do |dir|
      write_plugin(dir, "echo", response({"registry.example" => {"username" => "x", "password" => "the-token"}}))
      attributes = {"serviceAccountTokenAudience" => "a", "requireServiceAccount" => true, "cacheType" => "ServiceAccount"}
      providers = CP.load(config_path: config(dir, [provider("echo", tokenAttributes: attributes)]), bin_dir: dir,
                          token_requester: ->(*_args, **_kw) { "the-token" },
                          service_account_reader: ->(_ns, _name) { {"metadata" => {"uid" => "u"}} })
      pod = {"metadata" => {"namespace" => "ns", "name" => "p", "uid" => "pu"}, "spec" => {"serviceAccountName" => "sa"}}

      assert_empty providers.lookup("registry.example/app", pod: pod)
    end
  end

  def test_config_validation_and_directory_merge
    Dir.mktmpdir do |dir|
      write_plugin(dir, "a", response({}))
      write_plugin(dir, "b", response({}))
      configs = File.join(dir, "configs")
      Dir.mkdir(configs)
      config(configs, [provider("a")], file: "10-a.yaml")
      config(configs, [provider("b")], file: "20-b.json")

      assert_equal %w[a b], CP.load(config_path: configs, bin_dir: dir).providers.map(&:name)
      config(configs, [provider("a")], file: "30-dup.yml")
      error = assert_raises(CP::ConfigError) { CP.load(config_path: configs, bin_dir: dir) }
      assert_match(/duplicate provider name "a"/, error.message)
    end
    errors = CP.validate([{"name" => "../x", "apiVersion" => "v9", "matchImages" => [], "defaultCacheDuration" => "-1m",
                           "tokenAttributes" => {"cacheType" => "Forever", "requireServiceAccount" => false,
                                                 "requiredServiceAccountAnnotationKeys" => ["k"], "optionalServiceAccountAnnotationKeys" => ["k"]}}])

    [%r{provider name cannot contain '/'}, /apiVersion: Unsupported value/, /at least 1 item in matchImages/, /must be greater than or equal to 0/,
     /serviceAccountTokenAudience: Required/, /requireServiceAccount cannot be false/, /cannot be both required and optional/,
     /cacheType: Unsupported value: "Forever"/].each do |pattern|
      assert(errors.any? { |error| error.match?(pattern) }, pattern.inspect)
    end
    assert_includes CP.validate([]), "providers: Required value: at least 1 item in plugins is required"
    assert(CP.validate([provider("x", tokenAttributes: {"serviceAccountTokenAudience" => "a", "requireServiceAccount" => true,
                                                        "cacheType" => "Token"})], sa_tokens: false)
             .any? { |error| error.include?("feature gate is disabled") })
    Dir.mktmpdir do |dir|
      assert_raises(CP::ConfigError) { CP.load(config_path: config(dir, [provider("missing")]), bin_dir: dir) }
    end
  end

  def test_url_glob_matching
    assert CP.urls_match?("*.gcr.io", "us.gcr.io/project/image:1")
    refute CP.urls_match?("*.gcr.io", "gcr.io/project/image")
    refute CP.urls_match?("*.gcr.io", "a.b.gcr.io/image")
    assert CP.urls_match?("registry.io:5000/team", "registry.io:5000/team/app")
    refute CP.urls_match?("registry.io:5000", "registry.io/app")
    refute CP.urls_match?("registry.io/team", "registry.io/other")
  end

  def test_the_keyring_prefers_pod_secrets_then_asks_the_providers
    Dir.mktmpdir do |dir|
      write_plugin(dir, "wi", response({"registry.example" => {"username" => "oauth", "password" => "x"}}))
      attributes = {"serviceAccountTokenAudience" => "a", "requireServiceAccount" => true, "cacheType" => "Token"}
      providers = CP.load(config_path: config(dir, [provider("wi", tokenAttributes: attributes)]), bin_dir: dir,
                          token_requester: ->(*_args, **_kw) { "t" },
                          service_account_reader: ->(_ns, _name) { {"metadata" => {"uid" => "sa-u"}} })
      pod = {"metadata" => {"namespace" => "ns", "name" => "p", "uid" => "pu"}, "spec" => {"serviceAccountName" => "sa"}}
      keyring = Rubernetes::Node::ImageCredentials.new(providers: providers, pod: pod)
      credential = keyring.lookup("registry.example/app:1")

      assert_equal "oauth", credential.username
      assert_equal({service_account: {uid: "sa-u", namespace: "ns", name: "sa"}}, credential.pull_secret)
      assert_equal({uid: "sa-u", namespace: "ns", name: "sa"}, keyring.service_account_for("registry.example/app:1"))
      keyring.add_secret({"type" => "kubernetes.io/dockerconfigjson", "metadata" => {"name" => "s", "uid" => "su", "namespace" => "ns"},
                          "data" => {".dockerconfigjson" => [JSON.generate({"auths" => {"registry.example" => {"username" => "secret",
                                                                                                               "password" => "p"}}})].pack("m0")}})

      assert_equal "secret", keyring.lookup("registry.example/app:1").username
    end
  end

  def test_agent_config_keys
    base = {"version" => 1, "logging" => {"level" => "info"},
            "processes" => {"rubernetes-agent" => {"node_name" => "n1", "api_server" => "https://127.0.0.1:6443",
                                                   "image_credential_provider" => {"config" => "/etc/cp.yaml", "bin_dir" => "/opt/cp"}}}}
    Rubernetes::Bootstrap::Config.new(process_name: "rubernetes-agent", data: base)
    bad = JSON.parse(JSON.generate(base))
    bad["processes"]["rubernetes-agent"]["image_credential_provider"]["config"] = "relative.yaml"
    assert_raises(Rubernetes::Bootstrap::Config::Error) { Rubernetes::Bootstrap::Config.new(process_name: "rubernetes-agent", data: bad) }
  end
end
