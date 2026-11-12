# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The Kubernetes client of a process, from its kubeconfig or API server
      # address; a node first obtains its client certificate.
      module ClientBuilder
        private

        def build_api_client(process)
          kubeconfig = process["kubeconfig"]
          context = process["context"]
          bootstrap_client_certificate!(process) if process["bootstrap_kubeconfig"] && kubeconfig
          if kubeconfig || context
            Client::KubernetesClient.from_kubeconfig(path: kubeconfig, context: context, **api_rate(process))
          else
            api_server = process["api_server"]
            raise Config::Error, "control-plane process requires api_server or kubeconfig/context" if api_server.to_s.empty?

            Client::KubernetesClient.new(server: api_server, **api_rate(process))
          end
        end

        def api_rate(process)
          {qps: process["kube_api_qps"], burst: process["kube_api_burst"]}.compact
        end

        # kubelet --bootstrap-kubeconfig: the node's client certificate is
        # requested with the bootstrap credentials (a bootstrap token) and the
        # kubeconfig written to use it, unless it already holds a valid one.
        def bootstrap_client_certificate!(process)
          bootstrap = Client::KubernetesClient.from_kubeconfig(path: process["bootstrap_kubeconfig"])
          context = bootstrap.context
          client_certificate_manager(process).bootstrap!(
            kubeconfig_path: process["kubeconfig"], bootstrap_client: bootstrap,
            server: context.server, ca_file: context.ca_file
          )
        end

        def client_certificate_manager(process)
          cert_dir = process["cert_dir"] || File.join(File.dirname(File.expand_path(process.fetch("kubeconfig"))), "pki")
          Node::ClientCertificateManager.new(node_name: process.fetch("node_name"), cert_dir: cert_dir)
        end
      end
    end
  end
end
