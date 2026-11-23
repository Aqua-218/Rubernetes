# frozen_string_literal: true

require_relative "schema/quantity"

module Rubernetes
  # The PVC evaluator tracks the requested, current, and pending target
  # VolumeAttributesClass until the storage resize or modification completes.
  module PVCQuotaUsage
    SCOPE = "VolumeAttributesClass"
    STORAGE_CLASS_SUFFIX = ".storageclass.storage.k8s.io/"

    module_function

    def scopes_include_class?(scopes, expressions)
      scopes.include?(SCOPE) || expressions.any? { |expression| expression["scopeName"] == SCOPE }
    end

    def matches?(claim, scopes, expressions)
      classes = volume_classes(claim)
      scopes.all? { |scope| scope == SCOPE && !classes.empty? } && expressions.all? do |expression|
        next false unless expression["scopeName"] == SCOPE

        values = Array(expression["values"])
        case expression["operator"]
        when "Exists" then !classes.empty?
        when "DoesNotExist" then classes.empty?
        when "In" then classes.intersect?(values)
        when "NotIn" then classes.empty? || classes.any? { |name| !values.include?(name) }
        else false
        end
      end
    end

    def volume_classes(claim)
      [claim.dig("spec", "volumeAttributesClassName"), claim.dig("status", "currentVolumeAttributesClassName"),
       claim.dig("status", "modifyVolumeStatus", "targetVolumeAttributesClassName")].compact.reject(&:empty?).uniq.sort
    end

    def usage(claim)
      values = {"persistentvolumeclaims" => 1, "count/persistentvolumeclaims" => 1}
      storage = storage_request(claim)
      values["requests.storage"] = storage if storage
      storage_class = claim.dig("spec", "storageClassName").to_s
      unless storage_class.empty?
        prefix = "#{storage_class}#{STORAGE_CLASS_SUFFIX}"
        values["#{prefix}persistentvolumeclaims"] = 1
        values["#{prefix}requests.storage"] = storage if storage
      end
      values
    end

    def storage_request(claim)
      request = claim.dig("spec", "resources", "requests", "storage")
      return if request.nil?

      allocated = claim.dig("status", "allocatedResources", "storage")
      [request, allocated].compact.map { |value| Schema::Quantity.parse(value.to_s).value }.max.ceil
    end

    def delta(claim, old)
      current = usage(claim)
      return current unless old

      previous = usage(old)
      current.each_with_object({}) do |(name, amount), changes|
        increase = amount - previous.fetch(name, 0)
        changes[name] = increase if increase.positive?
      end
    end
  end
end
