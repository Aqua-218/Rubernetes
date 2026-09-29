# frozen_string_literal: true

require "etc"
require "socket"

module Rubernetes
  module Node
    # Host capacity the way kubelet's cAdvisor-backed node status reports
    # it: CPUs, memory, ephemeral storage under the Pod root, the Pod count
    # limit and hugepages.  Allocatable equals capacity minus the configured
    # reservations (none by default), which is also what a kubelet without
    # --system-reserved/--kube-reserved reports.
    module HostResources
      DEFAULT_MAX_PODS = 110

      module_function

      def capacity(pod_root: nil, max_pods: DEFAULT_MAX_PODS, meminfo: "/proc/meminfo", hugepages_root: "/sys/kernel/mm/hugepages")
        result = {
          "cpu" => Etc.nprocessors.to_s,
          # cadvisor MemoryCapacity in bytes, as a BinarySI quantity.
          "memory" => binary_quantity(memory_kib(meminfo) * 1024),
          "pods" => Integer(max_pods).to_s
        }
        bytes = ephemeral_storage_bytes(pod_root)
        result["ephemeral-storage"] = binary_quantity(bytes) if bytes
        pools = hugepage_pools(hugepages_root)
        if pools.empty?
          hugepages(meminfo).each { |size, quantity| result["hugepages-#{size}"] = quantity }
        else
          pools.each { |name, quantity| result[name] = quantity }
        end
        result
      end

      # cadvisor machine.HugePages: every page size under
      # /sys/kernel/mm/hugepages, even one with no pages ("hugepages-1Gi": "0").
      def hugepage_pools(root)
        return {} unless File.directory?(root)

        Dir.children(root).sort.each_with_object({}) do |entry, result|
          size_kib = entry[/\Ahugepages-(\d+)kB\z/, 1]
          next unless size_kib

          pages = Integer(File.read(File.join(root, entry, "nr_hugepages")).strip, 10)
          page_bytes = Integer(size_kib) * 1024
          result["hugepages-#{binary_quantity(page_bytes)}"] = binary_quantity(page_bytes * pages)
        rescue SystemCallError, ArgumentError
          next
        end
      end

      def binary_quantity(bytes)
        require_relative "../resource_helpers"
        Rubernetes::ResourceHelpers::Quantity.new(Rational(bytes), :binary_si).to_s
      end

      def allocatable(capacity, reserved: {})
        capacity.each_with_object({}) do |(name, value), result|
          reservation = reserved[name] || reserved[name.to_sym]
          result[name] = reservation ? subtract(value, reservation) : value
        end
      end

      def node_info
        release = uname_release
        {
          "kernelVersion" => release,
          "osImage" => os_image,
          "machineID" => read_first_line("/etc/machine-id"),
          "systemUUID" => read_first_line("/sys/class/dmi/id/product_uuid"),
          "bootID" => read_first_line("/proc/sys/kernel/random/boot_id")
        }.compact
      end

      def memory_kib(meminfo)
        return 0 unless File.file?(meminfo)

        File.foreach(meminfo) do |line|
          return Integer(line.split[1]) if line.start_with?("MemTotal:")
        end
        0
      rescue SystemCallError
        0
      end

      # Hugepages capacity per page size, as kubelet reports (`hugepages-2Mi`).
      def hugepages(meminfo)
        return {} unless File.file?(meminfo)

        size_kib = nil
        total = nil
        File.foreach(meminfo) do |line|
          size_kib = Integer(line.split[1]) if line.start_with?("Hugepagesize:")
          total = Integer(line.split[1]) if line.start_with?("HugePages_Total:")
        end
        return {} if size_kib.nil? || total.nil?

        label = size_kib >= 1024 * 1024 ? "#{size_kib / (1024 * 1024)}Gi" : "#{size_kib / 1024}Mi"
        {label => "#{total * size_kib}Ki"}
      rescue SystemCallError
        {}
      end

      def ephemeral_storage_bytes(pod_root)
        path = pod_root && File.directory?(pod_root) ? pod_root : "/var/lib"
        require_relative "../platform/linux/statfs"
        return nil unless Rubernetes::Platform::Linux::Statfs.supported?

        Rubernetes::Platform::Linux::Statfs.statfs(path).capacity_bytes
      rescue StandardError
        nil
      end

      def subtract(value, reservation)
        require_relative "resource_manager"
        manager = ResourceManager.new
        left = manager.parse_quantity(value)
        right = manager.parse_quantity(reservation)
        manager.format_quantity([left - right, 0].max)
      rescue StandardError
        value
      end

      def uname_release
        read_first_line("/proc/sys/kernel/osrelease") || ""
      end

      def os_image
        return "" unless File.file?("/etc/os-release")

        File.foreach("/etc/os-release") do |line|
          return line.split("=", 2).last.strip.delete('"') if line.start_with?("PRETTY_NAME=")
        end
        ""
      rescue SystemCallError
        ""
      end

      def read_first_line(path)
        return nil unless File.file?(path)

        File.open(path) { |file| file.gets&.strip }
      rescue SystemCallError
        nil
      end
    end
  end
end
