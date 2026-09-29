# frozen_string_literal: true

module Rubernetes
  # pkg/quota/v1/evaluator/core/resource_claims.go (v1.36.2) Usage: a
  # ResourceClaim counts as one count/resourceclaims.resource.k8s.io and, per
  # device class, as the devices it may take --
  # <class>.deviceclass.resource.k8s.io/devices: an exact count, "All" as the
  # 32 an allocation can hold at most, and a firstAvailable request as its
  # largest alternative per class.
  module ClaimQuotaUsage
    COUNT = "count/resourceclaims.resource.k8s.io"
    PER_CLASS_SUFFIX = ".deviceclass.resource.k8s.io/devices"
    ALLOCATION_RESULTS_MAX_SIZE = 32

    module_function

    def usage(claim)
      result = Hash.new(0)
      result[COUNT] = 1
      Array(claim.dig("spec", "devices", "requests")).each do |request|
        if !Array(request["firstAvailable"]).empty?
          largest = Hash.new(0)
          request["firstAvailable"].each do |sub|
            name = per_class(sub["deviceClassName"])
            count = devices(sub)
            largest[name] = count if count > largest[name]
          end
          largest.each { |name, count| result[name] += count }
        elsif request["exactly"]
          result[per_class(request.dig("exactly", "deviceClassName"))] += devices(request["exactly"])
        end
      end
      result
    end

    def per_class(name) = "#{name}#{PER_CLASS_SUFFIX}"

    def devices(request)
      case request["allocationMode"].to_s
      when "ExactCount" then Integer(request["count"] || 1)
      when "All" then ALLOCATION_RESULTS_MAX_SIZE
      else 0
      end
    end

    def matches?(name) = name == COUNT || name.to_s.end_with?(PER_CLASS_SUFFIX)
  end
end
