# frozen_string_literal: true

# Complete doubles of what Node::Agent is handed: the API port, the Pod
# lifecycle and the sync loop.  The agent calls its collaborators without
# asking what they respond to, so a double has to offer everything the real
# class does; tests subclass these and override the few methods they watch.
# Kept out of the test files: a test file that requires another one loads it
# twice under the Minitest inventory.
module NodeAgentFakes
  READY_REPORT = {"ready" => true, "errors" => [], "blocked" => []}.freeze

  # The registration port every API offers (see Node::Agent::APIPort): the
  # Node and the Lease, recorded.  The agent takes an API without a client
  # for exactly this and asks it for nothing else.
  class API
    attr_reader :nodes, :leases

    def initialize
      @nodes = []
      @leases = []
      @mutex = Mutex.new
    end

    def register_node(node) = @mutex.synchronize { (@nodes << node).last }
    def renew_lease(lease) = @mutex.synchronize { (@leases << lease).last }
    def last_node = @mutex.synchronize { @nodes.last }
  end

  # Node::APIClientAdapter as the agent sees it (Node::Agent#node_adapter?):
  # the registration port plus a Kubernetes client, object reads, Node status
  # patches and Pod deletes.
  class AdapterAPI < API
    attr_reader :client, :status_patches, :deleted_pods

    def initialize(client = nil)
      super()
      @client = client
      @status_patches = []
      @deleted_pods = []
    end

    def node_created? = false
    def read_object(_resource, _name, **) = nil
    def patch_node_status(name, status) = @status_patches << [name, status]
    def delete_pod(namespace:, name:, uid: nil) = @deleted_pods << [namespace, name, uid]
  end

  # Node::Lifecycle as the agent sees it: no Pods, a clean recovery.
  class Lifecycle
    attr_accessor :volumes_in_use_observer, :wakeup, :metrics_observer
    attr_reader :reported_in_use

    def initialize
      @reported_in_use = []
    end

    def runtime = nil
    def pod_volumes = nil
    def resource_reader = nil

    def recover(**) = READY_REPORT.dup
    def reconcile(_pod, **) = nil
    def pod_removed(_uid) = nil

    def record(_uid) = nil
    def records = {}
    def admitted_pods(**) = []
    def pods_on_node = []
    def image_roots_in_use = []
    def running_pod_uids = []
    def container_states(_uid) = []

    def observe_exits(_uid, *) = nil
    def retry_pending_cleanups(**) = nil
    def request_eviction(_uid, **) = true
    def evict(_pod, **) = nil

    def volumes_in_use = []
    def mark_volumes_reported_in_use(names) = @reported_in_use << names
  end

  # Node::SyncLoop as the agent sees it.  A block stands for the Pod worker:
  # it is called with each Pod the agent enqueues and its action.
  class SyncLoop
    attr_reader :enqueued

    def initialize(&worker)
      @worker = worker
      @enqueued = []
    end

    def start(**) = true
    def stop(**) = true
    def run_once(**) = true
    def running? = false
    def cache = {}

    def enqueue_pod(pod, action:, **)
      @enqueued << [pod, action]
      @worker&.call(pod, action)
      true
    end
  end
end
