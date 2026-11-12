# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # The Node object this agent reports: conditions, capacity, the runtime
      # handlers it serves and what the kubelet says about itself.
      module NodeObject
        def node
          build_node(ready: ready?)
        end

        alias registration node

        private

        def build_node(ready:, reason: nil, message: nil)
          timestamp = iso8601(time_value(nil))
          # ReadyCondition: the shutdown manager's error makes the node NotReady.
          if ready && (shutdown = @shutdown_manager&.shutdown_status)
            ready = false
            reason = "KubeletNotReady"
            message = shutdown
          end
          conditions = [ready_condition(ready, reason, message, timestamp), *pressure_conditions(timestamp)]
          Helpers.immutable(
            "apiVersion" => "v1",
            "kind" => "Node",
            "metadata" => {"name" => @node_name, "labels" => @node_labels, "annotations" => @node_annotations},
            "spec" => {},
            "status" => node_status(conditions)
          )
        end

        # setNodeReadyCondition: the transition time moves only when the
        # status does; the heartbeat on every build.
        def ready_condition(ready, reason, message, timestamp)
          message = "kubelet is posting ready status" if ready && message.nil?
          status = ready ? "True" : "False"
          transition = @pressure_mutex.synchronize do
            previous = @ready_condition
            moment = previous && previous[0] == status ? previous[1] : timestamp
            @ready_condition = [status, moment]
            moment
          end
          {
            "type" => "Ready",
            "status" => status,
            "reason" => reason || (ready ? "KubeletReady" : "KubeletNotReady"),
            "message" => message.to_s,
            "lastHeartbeatTime" => timestamp,
            "lastTransitionTime" => transition
          }
        end

        def node_status(conditions)
          {
            "capacity" => @capacity.merge(device_capacity.first),
            "allocatable" => @allocatable.merge(device_capacity.last),
            "addresses" => @addresses,
            "conditions" => conditions,
            # The API server proxies logs/exec/attach/port-forward to this port;
            # a Node without it cannot serve any streaming subresource.
            # v1.DaemonEndpoint's JSON field is "Port" with a capital P
            # (types.go: `json:"Port"`), unlike every neighbouring field.
            # Writing "port" made the API server drop it and default the
            # endpoint to 0, so every logs/exec/attach/port-forward request
            # was proxied to the standard kubelet port instead of this node's.
            "daemonEndpoints" => @streaming_port ? {"kubeletEndpoint" => {"Port" => @streaming_port}} : nil,
            # kubelet_node_status.go: set on every status update while the gate is on.
            "declaredFeatures" => @declared_features,
            "images" => @status_images&.images,
            "volumesInUse" => volumes_in_use,
            "runtimeHandlers" => @runtime_handlers,
            # SupplementalGroupsPolicy: Merge and Strict both honoured.
            "features" => @runtime_handlers ? {"supplementalGroupsPolicy" => true} : nil,
            "nodeInfo" => node_info
          }.compact
        end

        def node_info
          @host_info.merge(
            "architecture" => @architecture,
            "operatingSystem" => @operating_system,
            "containerRuntimeVersion" => "rubernetes://#{Rubernetes::VERSION}",
            "kubeletVersion" => Rubernetes::KUBERNETES_GIT_VERSION,
            # DisableNodeKubeProxyVersion is locked on in v1.36: the field
            # is left empty.
            "kubeProxyVersion" => "",
            "osImage" => @host_info["osImage"].to_s.empty? ? @operating_system : @host_info["osImage"]
          )
        end

        # nodestatus MemoryPressureCondition / DiskPressureCondition /
        # PIDPressureCondition: from the eviction manager's node conditions,
        # lastTransitionTime moving only when the status does.
        def pressure_conditions(timestamp)
          active = @eviction_manager ? @eviction_manager.node_conditions : []
          @pressure_mutex.synchronize do
            PRESSURE_CONDITIONS.map do |type, (pressured, clear)|
              on = active.include?(type)
              reason, message = on ? pressured : clear
              status = on ? "True" : "False"
              previous = @pressure_conditions[type]
              transition = previous && previous[0] == status ? previous[1] : timestamp
              @pressure_conditions[type] = [status, transition]
              {"type" => type, "status" => status, "reason" => reason, "message" => message,
               "lastHeartbeatTime" => timestamp, "lastTransitionTime" => transition}
            end
          end
        end

        def volumes_in_use
          names = @lifecycle.volumes_in_use
          names.empty? ? nil : names
        end

        # [capacity, allocatable] of the device plugin resources, as quantities.
        def device_capacity
          return [{}, {}] unless @device_plugins

          capacity, allocatable = @device_plugins.capacity
          [capacity.transform_values(&:to_s), allocatable.transform_values(&:to_s)]
        end

        def node_reference
          {"apiVersion" => "v1", "kind" => "Node", "name" => @node_name, "uid" => @node_name}
        end

        def cri_clients
          (runtime_backends || {}).values.select { |backend| cri_backend?(backend) }.map(&:client).uniq
        end

        # nodestatus.RuntimeHandlers: the default handler ("") and every handler
        # the node serves, with the features each really has: the native
        # runtime applies recursive read-only mounts where mount_setattr(2)
        # exists (5.12) and user namespaces; a microVM neither; a CRI runtime
        # what its Status reports.
        def node_runtime_handlers
          kernel = HostResources.uname_release.to_s[/\A(\d+)\.(\d+)/] ? [Regexp.last_match(1).to_i, Regexp.last_match(2).to_i] : [0, 0]
          native = {"recursiveReadOnlyMounts" => (kernel <=> [5, 12]) >= 0, "userNamespaces" => true}
          cri_features = {}
          served = (runtime_backends || {"rubernetes-native" => @runtime}).map do |name, backend|
            features = if cri_backend?(backend)
                         cri_features[backend.client] ||= cri_handler_features(backend.client)
                         cri_features[backend.client].fetch(backend.handler, cri_features[backend.client].fetch("", {}))
                       elsif name.to_s.start_with?("rubernetes-firecracker")
                         {"recursiveReadOnlyMounts" => false, "userNamespaces" => false}
                       else
                         native
                       end
            {"name" => name.to_s, "features" => features}
          end
          [{"name" => "", "features" => native}, *served]
        end
      end
    end
  end
end
