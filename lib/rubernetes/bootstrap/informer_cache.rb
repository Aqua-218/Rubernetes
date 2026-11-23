# frozen_string_literal: true

require "json"
require_relative "../controller/support"
require_relative "../watch/indexer"

module Rubernetes
  module Bootstrap
    # One informer's cache presented as a read source: objects only, and only
    # once the reflector has completed its initial list.
    class InformerCache
      attr_reader :object_index

      def initialize(informer, namespaced: false, index_selectors: false)
        @informer = informer
        index = informer.indexer
        @namespaced = namespaced
        index.add_index(:namespace) { |object| Controller::Support.namespace(object).to_s } if namespaced
        @object_index = index if index.is_a?(Watch::Indexer) && index.metadata_keys?
        @index_selectors = index_selectors && namespaced && @object_index
        index.add_index(:selector) { |object| selector_bucket(object) } if @index_selectors
      end

      def synced? = !@informer.reflector.resource_version.nil?

      def list = @informer.indexer.list

      def list_namespace(namespace)
        return @informer.indexer.by_index(:namespace, namespace) if @namespaced

        list.select { |object| Controller::Support.namespace(object).to_s == namespace }
      end

      # A selector with an equality requirement can only match events carrying
      # that pair. Expression-only and empty selectors share a namespace bucket.
      def selector_candidates(object)
        namespace = Controller::Support.namespace(object)
        return unless @index_selectors && namespace

        buckets = [namespace.to_json]
        Controller::Support.labels(object).each_pair { |key, value| buckets << [namespace, key.to_s, value.to_s].to_json }
        @object_index.by_index_values(:selector, buckets)
      end

      private def selector_bucket(object)
        namespace = Controller::Support.namespace(object).to_s
        selector = Controller::Support.value(Controller::Support.spec(object), "selector")
        if selector.is_a?(Hash)
          selector = Controller::Support.value(selector, "matchLabels") if Controller::Support.structured_label_selector?(selector)
          pair = selector.find { |_, expected| !expected.is_a?(Array) } if selector.is_a?(Hash)
          return [namespace, pair.first.to_s, pair.last.to_s].to_json if pair
        end
        namespace.to_json
      end

      # Write-through: an object this process just created/updated/deleted is
      # visible to the next reconcile immediately instead of after the watch
      # round-trip.  client-go controllers cover the same window with
      # ControllerExpectations; without either, a ReplicationController that
      # was re-queued by its own status write created a fresh Pod on every
      # pass (49 Pods for replicas: 2).
      # The object's own ADDED event may have put it there first.
      def add(object)
        @informer.indexer.add(object)
      rescue KeyError
        nil
      end

      # The response to a write tells the cache about a newer version of an
      # object the cache holds, and nothing else.  Applied unconditionally it
      # brought objects back from the dead: removing the last finalizer of a
      # PersistentVolumeClaim under deletion answers with the claim, the
      # claim's DELETED event had already emptied the entry, and the claim
      # then sat in the cache for good -- its volume stayed Bound to it.
      #
      # The API server deletes an object once both its finalizers and grace period are gone.
      def update(object)
        return @informer.indexer.delete(object) if finalized?(object)

        @informer.indexer.refresh(object)
      end

      def finalized?(object)
        metadata = object["metadata"] || {}
        return false if object["kind"] == "Namespace" && !Array(object.dig("spec", "finalizers")).empty?

        !metadata["deletionTimestamp"].nil? && Array(metadata["finalizers"]).empty? && metadata["deletionGracePeriodSeconds"].to_i.zero?
      end

      def delete(object) = @informer.indexer.delete(object)
    end
  end
end
