#!/usr/bin/env ruby
# frozen_string_literal: true

# Machine-readable view of the pinned upstream inputs.  Every value the
# conformance lanes rely on comes from third_party/locks/; nothing here
# resolves a tag, a branch head or `latest` over the network.
#
# See spec/verification/kubernetes-compatibility.md "Pinned Upstream Inputs".

require "digest"
require "json"

module Conformance
  module Lock
    ROOT = File.expand_path("../..", __dir__)
    KUBERNETES = File.join(ROOT, "third_party/locks/kubernetes-v1.36.2.json")
    RUNNERS = File.join(ROOT, "third_party/locks/conformance-runners.json")
    PROFILES = File.join(ROOT, "test/conformance/kubernetes/profiles.yml")

    module_function

    def kubernetes
      @kubernetes ||= JSON.parse(File.read(KUBERNETES)).freeze
    end

    def runners
      @runners ||= JSON.parse(RUNNERS ? File.read(RUNNERS) : "{}").freeze
    end

    def source_commit
      kubernetes.fetch("source").fetch("commit")
    end

    def tag_object
      kubernetes.fetch("source").fetch("tag_object")
    end

    def conformance_definition
      kubernetes.fetch("conformance_definition")
    end

    def conformance_image_digest
      kubernetes.fetch("conformance_image").fetch("index_digest")
    end

    def platform_digest(platform)
      kubernetes.fetch("conformance_image").fetch("platforms").fetch(platform)
    end

    def support_images
      kubernetes.fetch("runner_support_images")
    end

    # The lock pins a tag plus an index digest; runners must be given the
    # digest form so a moved tag cannot change what is executed.  The tag is
    # the part after the last ":" only when that part contains no "/", so a
    # registry host:port is left alone.
    def reference_by_digest(image)
      reference = image.fetch("reference").to_s
      digest = image.fetch("index_digest").to_s
      head, separator, tail = reference.rpartition(":")
      repository = !separator.empty? && !tail.include?("/") ? head : reference
      "#{repository}@#{digest}"
    end

    def runner(name)
      runners.fetch(name)
    end

    def runner_artifact(name, platform = "linux/amd64")
      runner(name).fetch("artifacts").fetch(platform)
    end

    # Profiles are a small fixed YAML document; parsing it with the stdlib
    # keeps the runner free of gem dependencies at K0 time.
    def profiles
      @profiles ||= begin
        require "yaml"
        YAML.safe_load_file(PROFILES).freeze
      end
    end

    def digest_file(path)
      Digest::SHA256.file(path).hexdigest
    end
  end
end
