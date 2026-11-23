# frozen_string_literal: true

require "json"
require "open3"

module Conformance
  # The project's cluster-scoped objects can be named independently of the
  # release namespace. Compare identities against the pre-install snapshot.
  class K6ProjectResidue
    # An installed CRD can share a plural with a built-in. In particular
    # Longhorn also serves volumeattachments while the chart is installed.
    RESOURCE_PATHS = {
      "/api/v1" => %w[persistentvolumes],
      "/apis/storage.k8s.io/v1" => %w[volumeattachments storageclasses csidrivers],
      "/apis/rbac.authorization.k8s.io/v1" => %w[clusterroles clusterrolebindings],
      "/apis/apiextensions.k8s.io/v1" => %w[customresourcedefinitions],
      "/apis/admissionregistration.k8s.io/v1" => %w[validatingwebhookconfigurations mutatingwebhookconfigurations],
      "/apis/apiregistration.k8s.io/v1" => %w[apiservices],
      "/apis/networking.k8s.io/v1" => %w[ingressclasses],
      "/apis/scheduling.k8s.io/v1" => %w[priorityclasses]
    }.each_with_object({}) do |(prefix, resources), paths|
      resources.each { |resource| paths[resource] = "#{prefix}/#{resource}" }
    end.freeze
    CLUSTER_RESOURCES = RESOURCE_PATHS.keys.freeze
    VOLUME_RECLAIM_SECONDS = 120

    def initialize(kubectl:, kubeconfig:)
      @command = [kubectl, "--kubeconfig", kubeconfig, "--request-timeout=20s"]
    end

    def snapshot(resources_to_check = CLUSTER_RESOURCES)
      resources = {}
      errors = []
      resources_to_check.each do |resource|
        document, error = get(resource)
        if error
          errors << error
        else
          resources[resource] = document.fetch("items", []).to_h { |item| [identity(item), item] }
        end
      end
      {resources: resources, errors: errors}
    end

    def residue(namespace, baseline, post: snapshot)
      issues = baseline.fetch(:errors) + post.fetch(:errors)
      document, error = get("namespace", namespace, "--ignore-not-found")
      if error
        issues << error
      elsif !document.empty?
        issues << {"kind" => "Namespace", "name" => namespace, "uid" => document.dig("metadata", "uid"),
                   "finalizers" => document.dig("spec", "finalizers") || document.dig("metadata", "finalizers")}
      end
      post.fetch(:resources).each do |resource, observed|
        before = baseline.fetch(:resources)[resource]
        next unless before

        issues.concat((observed.keys - before.keys).map do |key|
          metadata = observed.fetch(key).fetch("metadata")
          {"kind" => resource, "name" => metadata["name"], "uid" => metadata["uid"], "finalizers" => metadata["finalizers"]}
        end)
      end
      issues
    end

    def reserve_namespace(namespace, baseline, webhook_labels:)
      raise "cannot verify the pre-install snapshot: #{baseline.fetch(:errors).inspect}" unless baseline.fetch(:errors).empty?

      webhooks = baseline.fetch(:resources).select { |resource, _items| resource.end_with?("webhookconfigurations") }
      conflicting = webhooks.values.flat_map(&:values).select do |item|
        !webhook_labels.empty? && webhook_labels.all? { |key, label| item.dig("metadata", "labels", key) == label }
      end
      raise "pre-existing webhooks match the chart's deletion selector: #{conflicting.map { |item| identity(item) }.inspect}" unless conflicting.empty?

      out, err, status = Open3.capture3(*@command, "create", "namespace", namespace, "-o", "json", binmode: true)
      raise "cannot reserve disposable namespace #{namespace}: #{err.force_encoding(Encoding::UTF_8).scrub.strip}" unless status.success?

      uid = JSON.parse(out).fetch("metadata").fetch("uid")
      raise "namespace #{namespace} has no baseline identity" if uid.to_s.empty?

      uid
    end

    def namespace_owned?(namespace, uid)
      document, error = get("namespace", namespace, "--ignore-not-found")
      error.nil? && document.dig("metadata", "uid") == uid
    end

    def missing_baseline_identities(before, after)
      before.fetch(:resources).flat_map do |resource, baseline|
        observed = after.fetch(:resources)[resource]
        next [] if observed.nil?

        (baseline.keys - observed.keys).map { |name, uid| {"kind" => resource, "name" => name, "uid" => uid} }
      end
    end

    def runtime_snapshot(observer, namespace, pv_snapshot: nil, check_workers: false, stage: nil)
      state = observer.snapshot(stage: stage)
      return state unless observer.available?

      verify_runtime_workers(state) if check_workers
      pods, error = get("pods", "--namespace", namespace)
      if error
        state.fetch(:errors) << "could not list Pod identities for #{namespace}"
      else
        pods.fetch("items", []).each do |pod|
          metadata = pod.fetch("metadata")
          state.fetch(:pods)[metadata.fetch("uid")] = metadata.fetch("namespace")
        end
      end
      volumes = pv_snapshot || snapshot(["persistentvolumes"])
      state.fetch(:errors).concat(volumes.fetch(:errors).map { "could not list PV identities" })
      state[:paths] = provisioned_paths(volumes.dig(:resources, "persistentvolumes") || {})
      state
    end

    # The binder releases PVCs after namespace deletion. CSI provisioners can
    # also wait for attachment deletion and retry before removing the PV.
    def await_volume_reclaim(namespace, baseline, post)
      kind = "persistentvolumes"
      before = baseline.dig(:resources, kind) || {}
      after = post.dig(:resources, kind) || {}
      reclaiming = (after.keys - before.keys).select do |key|
        spec = after.fetch(key)["spec"] || {}
        spec["persistentVolumeReclaimPolicy"] == "Delete" && spec.dig("claimRef", "namespace") == namespace
      end
      return false if reclaiming.empty?

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + VOLUME_RECLAIM_SECONDS
      loop do
        document, error = get(kind)
        break if error || (document.fetch("items").map { |item| identity(item) } & reclaiming).empty?
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 1
      end
      true
    end

    private

    def verify_runtime_workers(state)
      document, error = get("nodes")
      if error
        state.fetch(:errors) << "could not list cluster worker identities"
        return
      end

      nodes = document.fetch("items").map { |node| node.fetch("metadata").fetch("name") }
      missing = nodes - state.fetch(:workers).keys
      missing.each { |node| state.fetch(:workers)[node] = "unmeasured" }
      state.fetch(:errors) << "node state is unavailable for #{missing.sort.join(", ")}" unless missing.empty?
    end

    def provisioned_paths(volumes)
      volumes.each_value.with_object({}) do |volume, paths|
        path = volume.dig("spec", "hostPath", "path")
        namespace = volume.dig("spec", "claimRef", "namespace")
        next unless path && namespace && File.basename(File.dirname(path)) == "persistent-volumes"

        paths[File.basename(path)] = namespace
      end
    end

    def identity(item)
      metadata = item.fetch("metadata")
      [metadata.fetch("name"), metadata["uid"]]
    end

    def get(resource, *args)
      request = if args.empty? && RESOURCE_PATHS.key?(resource)
                  ["--raw", RESOURCE_PATHS.fetch(resource)]
                else
                  [resource, *args, "-o", "json"]
                end
      out, err, status = Open3.capture3(*@command, "get", *request, binmode: true)
      return [nil, check_failed(resource, err.force_encoding(Encoding::UTF_8).scrub.lines.last(5).join.strip)] unless status.success?

      [out.empty? ? {} : JSON.parse(out.force_encoding(Encoding::UTF_8)), nil]
    rescue JSON::ParserError => error
      [nil, check_failed(resource, error.message)]
    end

    def check_failed(resource, error)
      {"kind" => "ResidueCheckFailed", "resource" => resource, "error" => error}
    end
  end
end
