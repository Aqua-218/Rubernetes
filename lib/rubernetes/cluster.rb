# frozen_string_literal: true

require "fileutils"
require "ipaddr"
require "json"
require "openssl"
require "rbconfig"
require "securerandom"
require "socket"
require "time"
require "yaml"

require_relative "client"
require_relative "consensus/identity"
require_relative "controller/registry"
require_relative "network/host_forward"

module Rubernetes
  # A whole cluster on one host: every component a real `exe/rubernetes-*`
  # process under its own configuration, the "nodes" told apart by their Pod
  # bridges.  `rubectl cluster up` and the conformance lanes both come here.
  module Cluster
    class Error < StandardError; end

    SOURCE_ROOT = File.expand_path("../..", __dir__)
    DEFAULT_STATE_DIR = "/var/lib/rubernetes/clusters"
    ADMIN_USER = "rubernetes-admin"
    BOOTSTRAP_GROUP = "system:bootstrappers:kubeadm:default-node-token"
    COREDNS_USER = "system:coredns"
    KUBELET_CLIENT_USER = "kube-apiserver-kubelet-client"
    # Service CIDRs per family (kube-apiserver --service-cluster-ip-range);
    # the primary family is the cluster's first.
    SERVICE_CIDRS = {"ipv4" => "10.96.0.0/12", "ipv6" => "fd00:d8:5::/112"}.freeze
    # A controller-only marker kind.  The garbage collector is identified by a
    # kind no apiserver ever serves because its subject is every object's
    # ownerReferences rather than one resource; filtered by served kinds it
    # was dropped, and nothing was ever garbage collected.
    CONTROLLER_ONLY_KINDS = %w[GarbageCollector].freeze
    # Where clusters of earlier bring-ups keep their descriptors.
    KNOWN_CLUSTER_GLOBS = %W[/srv/*/cluster.json /srv/*/*/cluster.json /srv/*/*/*/cluster.json
                             #{DEFAULT_STATE_DIR}/*/cluster.json].freeze
    # Ruby's default GC thresholds are sized for short scripts.  A node agent
    # starting thirty Pods at once allocated past the 16 MB malloc limit
    # every few hundred milliseconds and ran 18 major collections (marking
    # 340k old objects each) in a 20 s burst -- a fifth of its CPU.  Larger
    # limits trade some resident memory for far fewer collections.  An
    # explicit value in the environment still wins.
    GC_ENVIRONMENT = {
      "RUBY_GC_MALLOC_LIMIT" => (64 << 20).to_s,
      "RUBY_GC_MALLOC_LIMIT_MAX" => (256 << 20).to_s,
      "RUBY_GC_OLDMALLOC_LIMIT" => (128 << 20).to_s,
      "RUBY_GC_OLDMALLOC_LIMIT_MAX" => (512 << 20).to_s,
      "RUBY_GC_HEAP_OLDOBJECT_LIMIT_FACTOR" => "3.0",
      # Ruby's own defaults, listed so an experiment can override them from
      # the environment like the values above.
      "RUBY_GC_HEAP_FREE_SLOTS_MIN_RATIO" => "0.20",
      "RUBY_GC_HEAP_GROWTH_FACTOR" => "1.8"
    }.freeze

    # `-I` arguments for a component process: this library, and the directory
    # the native extension was built into (the source tree's build directory,
    # or wherever RubyGems put it for an installed gem).
    def self.load_path_arguments
      extension = [File.join(SOURCE_ROOT, "build/ext/rubernetes_linux"), *$LOAD_PATH].find do |directory|
        File.file?(File.join(directory, "rubernetes_linux.so"))
      end
      [File.join(SOURCE_ROOT, "lib"), extension].compact.flat_map { |directory| ["-I", directory] }
    end
  end
end

require_relative "cluster/processes"
require_relative "cluster/pki"
require_relative "cluster/host"
require_relative "cluster/configs"
require_relative "cluster/readiness"
require_relative "cluster/provisioner"
