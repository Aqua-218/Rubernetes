# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # What the agent asks of the injected API.  Every API registers the Node
      # (#register_node) and renews its Lease (#renew_lease); that is the whole
      # contract of a registration-only port (the crash harness has one).  The
      # node's own adapter (APIClientAdapter) adds the rest: see
      # Agent#node_adapter?.
      module APIPort
        private

        def write_node(object)
          return @api.register_node(object) if @register_node

          @api.register_node(object, create: false) if node_adapter?
        end

        def persist_lease(object)
          @api.renew_lease(object)
        end

        # The Kubernetes client behind the adapter, for the managers that
        # speak to the API themselves (events, DRA, CSI, Pod certificates).
        def api_client(api = @api)
          node_adapter?(api) ? api.client : nil
        end

        # RecordNodeRegistered: only the adapter knows whether its write
        # created the Node.
        def api_created_node?
          node_adapter? && @api.node_created?
        end

        # The final delete of a gracefully deleted Pod: the API server set its
        # deletionTimestamp and waits for the kubelet to confirm the containers
        # are gone (upstream's status manager does this, with grace 0 and a
        # UID precondition -- APIClientAdapter#delete_pod).  Nil for a
        # registration-only API.
        def pod_deleter_for(api)
          return nil unless node_adapter?(api)

          lambda { |namespace:, name:, uid: nil|
            api.delete_pod(namespace: namespace, name: name, uid: uid)
          }
        end

        # The Node's labels as the API server holds them now, for admission.
        def live_node_labels_provider(api)
          return nil unless node_adapter?(api)

          lambda do
            node = api.read_object("nodes", @node_name)
            labels = node.is_a?(Hash) ? node.dig("metadata", "labels") : nil
            labels.is_a?(Hash) ? @node_labels.merge(labels) : nil
          end
        end

        def refresh_node_taints
          return unless node_adapter?

          remember_node_taints(@api.read_object("nodes", @node_name))
        rescue Client::Error, SystemCallError => error
          @error_handler&.call(error, :admission_node_taints)
          nil
        end
      end
    end
  end
end
