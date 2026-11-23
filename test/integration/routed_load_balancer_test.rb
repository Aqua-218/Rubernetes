# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class RoutedLoadBalancerTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "open3"
    require "tmpdir"
    require "timeout"
    require "rubernetes/bootstrap/config"
    require "rubernetes/bootstrap/structured_logger"
    require "rubernetes/bootstrap/api_server_service"
    require "rubernetes/bootstrap/control_plane_services"
    require "rubernetes/cluster"

    VIP = "198.51.100.10"
    NODE_IP = "192.0.2.1"
    CLIENT_IP = "192.0.2.2"
    PORT = 18080
    ENDPOINT_PORT = 18081
    FINALIZER = Rubernetes::Controller::RoutedLoadBalancer::FINALIZER
    CLASS = Rubernetes::Network::LoadBalancerPool::CLASS_NAME
    DEFAULT_ROUTED = ARGV.include?("default-routed")
    Bootstrap = Rubernetes::Bootstrap

    def wait_for(description)
      Timeout.timeout(35) do
        loop do
          found = yield
          return found if found

          sleep 0.05
        end
      end
    rescue Timeout::Error
      raise "timed out waiting for #{description}"
    end

    def lookup(client, name)
      client.get("services", name, namespace: "default")
    rescue Rubernetes::Client::APIError => error
      raise unless error.status.to_i == 404

      nil
    end

    def config(name, configuration)
      Bootstrap::Config.new(process_name: name,
                            data: {"version" => 1, "logging" => {"level" => "warn"}, "processes" => {name => configuration}}).process
    end

    def service(client, name, extra = {}, finalizers: [])
      base = {"type" => "LoadBalancer", "loadBalancerClass" => CLASS, "allocateLoadBalancerNodePorts" => false,
              "ports" => [{"name" => "http", "protocol" => "TCP", "port" => PORT, "targetPort" => ENDPOINT_PORT}]}
      client.create({"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => name, "namespace" => "default", "finalizers" => finalizers},
                     "spec" => base.merge(extra)})
    end

    def ingress(service)
      service&.dig("status", "loadBalancer", "ingress", 0, "ip")
    end

    def run(*args)
      system(*args, exception: true)
    end

    def packet(command)
      Open3.capture2e("timeout", "1", *command, RbConfig.ruby, "-rsocket", "-e",
                      "s = TCPSocket.new(ARGV[0], Integer(ARGV[1])); puts s.gets", VIP, PORT.to_s)
    end

    Dir.mktmpdir("routed-load-balancer-") do |root|
      begin
        input, output, client_namespace = Open3.popen2("unshare", "--net", RbConfig.ruby, "-e", "puts Process.pid; STDOUT.flush; STDIN.read")
        raise "client network namespace did not start" unless output.wait_readable(5) && Integer(output.gets) == client_namespace.pid

        ns = ["nsenter", "--target", client_namespace.pid.to_s, "--net", "--"]
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "vip-node", "type", "veth", "peer", "name", "vip-client", "netns", client_namespace.pid.to_s)
        run("ip", "link", "set", "vip-node", "up")
        run("ip", "addr", "add", "#{NODE_IP}/24", "dev", "vip-node")
        run(*ns, "ip", "link", "set", "vip-client", "up")
        run(*ns, "ip", "addr", "add", "#{CLIENT_IP}/24", "dev", "vip-client")
        run(*ns, "ip", "route", "add", "#{VIP}/32", "via", NODE_IP)

        origin = TCPServer.new(NODE_IP, ENDPOINT_PORT)
        origin_thread = Thread.new do
          loop do
            peer = origin.accept
            peer.puts "routed-endpoint"
            peer.close
          end
        end

        provisioner = Rubernetes::Cluster::Provisioner.new(root: root, controls: 1, workers: 1, datastore: "memory",
                                                         identities: :components, load_balancer_pool: ["#{VIP}/32"])
        pki = provisioner.issue_pki
        ports = provisioner.allocate_ports
        api_path = provisioner.write_apiserver_config("control-0", ports, pki)
        logger = Bootstrap::StructuredLogger.new(process_name: "routed-lb-test", level: "warn", io: $stderr)
        api = Bootstrap::APIServerService.new(config: Bootstrap::Config.load(process_name: "rubernetes-apiserver", path: api_path).process,
                                              logger: logger).start
        endpoint = "https://127.0.0.1:#{api.http_server.port}"
        admin_config = provisioner.write_kubeconfig(endpoint, pki)
        admin = provisioner.api_client(admin_config)
        rbac = YAML.safe_load_file("config/addons/routed-load-balancer-rbac.yml")
        provisioner.apply!(admin_config, rbac, "the routed LoadBalancer controller's RBAC")

        controller_kubeconfig = provisioner.component_kubeconfig(endpoint, pki, "kube-controller-manager", nil)
        controller_client = provisioner.api_client(controller_kubeconfig)
        controller_config = config("rubernetes-controller-manager",
                                   {"controllers" => ["service-lb-controller"], "load_balancer_pool" => ["#{VIP}/32"],
                                    "default_routed_load_balancer" => DEFAULT_ROUTED,
                                    "use_service_account_credentials" => true,
                                    "sync" => {"interval_seconds" => 0.1}})
        controller = Bootstrap::ControllerManagerService.new(config: controller_config, logger: logger, client: controller_client).start
        proxy_client = provisioner.api_client(provisioner.component_kubeconfig(endpoint, pki, "kube-proxy", nil))
        proxy_config = config("rubernetes-proxy", {"node_name" => "worker-0", "backend" => "nftables", "attach" => true})
        proxy = Bootstrap::ProxyService.new(config: proxy_config, logger: logger, client: proxy_client).start

        requested_class = DEFAULT_ROUTED ? nil : CLASS
        service(admin, "routed-a", {"loadBalancerClass" => requested_class})
        service(admin, "routed-b", {"loadBalancerClass" => requested_class})
        cloud_finalizer = "service.kubernetes.io/load-balancer-cleanup"
        service(admin, "cloud-owned", {"loadBalancerClass" => nil}, finalizers: DEFAULT_ROUTED ? [cloud_finalizer] : [])
        service(admin, "foreign-class", {"loadBalancerClass" => "example.test/custom"})
        wait_for("a reservation and the waiting Service's finalizer") do
          pair = %w[routed-a routed-b].map { |name| lookup(admin, name) }
          pair.count { |item| ingress(item) == VIP } == 1 && pair.all? { |item| Array(item.dig("metadata", "finalizers")).include?(FINALIZER) }
        end
        published = %w[routed-a routed-b].find { |name| ingress(lookup(admin, name)) == VIP }
        pending = (%w[routed-a routed-b] - [published]).first
        %w[cloud-owned foreign-class].each do |name|
          raise "foreign Service #{name} was claimed" if lookup(admin, name).dig("metadata", "finalizers").to_a.include?(FINALIZER)
        end
        first = lookup(admin, published)
        raise "VIP ipMode missing" unless first.dig("status", "loadBalancer", "ingress", 0, "ipMode") == "VIP"
        raise "allocation changed Service class" unless first.dig("spec", "loadBalancerClass") == requested_class
        admin.create({"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
                      "metadata" => {"name" => "origin", "namespace" => "default", "labels" => {"kubernetes.io/service-name" => published}},
                      "addressType" => "IPv4", "ports" => [{"name" => "http", "port" => ENDPOINT_PORT, "protocol" => "TCP"}],
                      "endpoints" => [{"addresses" => [NODE_IP], "conditions" => {"ready" => true}, "nodeName" => "worker-0"}]})
        wait_for("TCP from client through the routed VIP") { packet(ns).first == "routed-endpoint\n" }

        controller.stop
        controller = Bootstrap::ControllerManagerService.new(config: controller_config, logger: logger, client: controller_client).start
        after_restart = lookup(admin, published)
        unless ingress(after_restart) == VIP && after_restart.dig("metadata", "resourceVersion") == first.dig("metadata", "resourceVersion")
          raise "restart changed the stable Service's VIP or resource version"
        end
        admin.patch("services", {"metadata" => {"finalizers" => [FINALIZER, "example.test/hold"]}},
                    type: :merge, namespace: "default", name: published)
        admin.delete("services", published, namespace: "default")
        wait_for("VIP withdrawal and removal of only the routed finalizer") do
          item = lookup(admin, published)
          item && item.dig("metadata", "finalizers") == ["example.test/hold"] && ingress(item).nil?
        end
        wait_for("withdrawn network forwarding") { !packet(ns).last.success? }
        wait_for("the released VIP to be assigned to the waiting Service") { ingress(lookup(admin, pending)) == VIP }
        admin.patch("services", {"metadata" => {"finalizers" => []}}, type: :merge, namespace: "default", name: published)
        wait_for("Service deletion") { lookup(admin, published).nil? }
        puts "routed-load-balancer-ok"
      ensure
        proxy&.stop
        controller&.stop
        api&.stop(reason: "test_complete")
        origin_thread&.kill&.join
        origin&.close
        input&.close
        output&.close
        client_namespace&.join(2)
      end
    end
  RUBY

  def test_vip_reaches_an_endpoint_from_another_network_namespace_and_is_released
    verify_routing
  end

  def test_opted_in_classless_vip_reaches_an_endpoint_and_is_released_without_claiming_foreign_services
    verify_routing("default-routed")
  end

  private

  def verify_routing(*)
    skip "requires a network namespace" unless system("unshare", "--net", "true", out: File::NULL, err: File::NULL)

    output, status = Open3.capture2e("timeout", "110", "unshare", "--net", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT, *)

    assert_predicate status, :success?, output
    assert_includes output, "routed-load-balancer-ok"
  end
end
