# frozen_string_literal: true

require "tmpdir"

repo = File.expand_path("../../../..", __dir__)
$LOAD_PATH.unshift(File.join(repo, "lib"))

require "rubernetes/bootstrap/config"
require "rubernetes/bootstrap/structured_logger"
require "rubernetes/bootstrap/api_server_service"
require "rubernetes/cluster"

bootstrap = Rubernetes::Bootstrap
Dir.mktmpdir("rubernetes-cloud-service-controller-") do |root|
  provisioner = Rubernetes::Cluster::Provisioner.new(root: root, controls: 1, workers: 1, datastore: "memory")
  pki = provisioner.issue_pki
  configuration = provisioner.write_apiserver_config("control-0", provisioner.allocate_ports, pki)
  config = bootstrap::Config.load(process_name: "rubernetes-apiserver", path: configuration).process
  logger = bootstrap::StructuredLogger.new(process_name: "cloud-service-controller-test", level: "warn", io: $stderr)
  api = bootstrap::APIServerService.new(config: config, logger: logger).start
  endpoint = "https://127.0.0.1:#{api.http_server.port}"
  admin_config = provisioner.write_kubeconfig(endpoint, pki)
  admin = provisioner.api_client(admin_config)
  account = "service-controller"
  path = "/api/v1/namespaces/kube-system/serviceaccounts/#{account}/token"
  admin.create({"kind" => "ServiceAccount", "apiVersion" => "v1", "metadata" => {"name" => account, "namespace" => "kube-system"}})
  admin.create({"kind" => "ClusterRoleBinding", "apiVersion" => "rbac.authorization.k8s.io/v1",
                "metadata" => {"name" => "external-ccm-test-route"},
                "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "ClusterRole",
                              "name" => "system:controller:route-controller"},
                "subjects" => [{"kind" => "ServiceAccount", "name" => account, "namespace" => "kube-system"}]})
  credential = admin.create(path, {"kind" => "TokenRequest", "apiVersion" => "authentication.k8s.io/v1",
                                   "spec" => {"audiences" => ["https://kubernetes.default.svc.cluster.local"]}})
  controller_config = YAML.safe_load_file(admin_config)
  identity = controller_config.fetch("users").first
  identity["user"] = {"token" => credential.dig("status", "token")}
  config_path = File.join(root, "kubeconfig-ccm")
  File.write(config_path, YAML.dump(controller_config), perm: 0o600)

  status = system("go", "run", ".", admin_config, config_path, provisioner.free_port.to_s,
                  pki.fetch(:ca), pki.fetch(:server), pki.fetch(:server_key), chdir: __dir__)
  abort "upstream cloud Service controller check failed" unless status
ensure
  admin&.close
  api&.stop(reason: "test_complete")
end
