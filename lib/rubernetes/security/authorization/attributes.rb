# frozen_string_literal: true

require_relative "../identity"

module Rubernetes
  module Security
    module Authorization
      # Request attributes for authorization (k8s.io/apiserver/pkg/authorization/authorizer).
      class Attributes
        attr_reader :user, :verb, :namespace, :api_group, :api_version, :resource, :subresource, :name, :path,
                    :field_selector, :label_selector

        def initialize(user:, verb:, path: nil, namespace: nil, api_group: "", api_version: "", resource: nil, subresource: nil,
                       name: nil, resource_request: nil, field_selector: nil, label_selector: nil)
          @user = user
          @verb = verb.to_s
          @path = path
          @namespace = namespace.nil? || namespace == :cluster || namespace == :all ? "" : namespace.to_s
          @api_group = api_group.to_s
          @api_version = api_version.to_s
          @resource = resource&.to_s
          @subresource = subresource.to_s.empty? ? "" : subresource.to_s
          @name = name.to_s
          @resource_request = resource_request.nil? ? !@resource.nil? : resource_request
          @field_selector = field_selector
          @label_selector = label_selector
        end

        # The same request asked with another verb (overrideVerb).
        def with_verb(verb)
          with(verb: verb)
        end

        # A copy with some attributes replaced.
        def with(**changes)
          self.class.new(user: changes.fetch(:user, @user), verb: changes.fetch(:verb, @verb), path: changes.fetch(:path, @path),
                         namespace: changes.fetch(:namespace, @namespace), api_group: changes.fetch(:api_group, @api_group),
                         api_version: changes.fetch(:api_version, @api_version), resource: changes.fetch(:resource, @resource),
                         subresource: changes.fetch(:subresource, @subresource), name: changes.fetch(:name, @name),
                         resource_request: changes.fetch(:resource_request, @resource_request),
                         field_selector: changes.fetch(:field_selector, @field_selector),
                         label_selector: changes.fetch(:label_selector, @label_selector))
        end

        def resource_request?
          @resource_request
        end

        def resource_with_subresource
          @subresource.empty? ? @resource.to_s : "#{@resource}/#{@subresource}"
        end

        # Attributes for SubjectAccessReview spec.
        def to_h
          hash = {"user" => @user.name, "groups" => @user.groups, "uid" => @user.uid, "extra" => @user.extra, "verb" => @verb}
          if resource_request?
            hash["resourceAttributes"] = {"namespace" => @namespace, "verb" => @verb, "group" => @api_group, "version" => @api_version,
                                          "resource" => @resource, "subresource" => @subresource, "name" => @name}
          else
            hash["nonResourceAttributes"] = {"path" => @path, "verb" => @verb}
          end
          hash
        end

        # Map an HTTP method + route to a Kubernetes verb
        # (k8s.io/apiserver/pkg/endpoints/request/requestinfo.go).
        def self.verb_for(method:, collection:, watch: false, name_present: true)
          case method.to_s.upcase
          when "GET", "HEAD"
            return "watch" if watch

            collection && !name_present ? "list" : "get"
          when "POST" then "create"
          when "PUT" then "update"
          when "PATCH" then "patch"
          when "DELETE" then collection && !name_present ? "deletecollection" : "delete"
          else method.to_s.downcase
          end
        end

        def self.non_resource_verb(method)
          case method.to_s.upcase
          when "GET", "HEAD" then "get"
          when "POST" then "post"
          when "PUT" then "put"
          when "PATCH" then "patch"
          when "DELETE" then "delete"
          else method.to_s.downcase
          end
        end
      end

      # Authorizer decision.
      class Decision
        ALLOW = :allow
        DENY = :deny
        NO_OPINION = :no_opinion

        attr_reader :verdict, :reason, :authorizer

        def initialize(verdict, reason: nil, authorizer: nil)
          @verdict = verdict
          @reason = reason
          @authorizer = authorizer
        end

        def self.allow(reason = nil, authorizer: nil) = new(ALLOW, reason: reason, authorizer: authorizer)
        def self.deny(reason = nil, authorizer: nil) = new(DENY, reason: reason, authorizer: authorizer)
        def self.no_opinion(reason = nil, authorizer: nil) = new(NO_OPINION, reason: reason, authorizer: authorizer)

        def allowed? = @verdict == ALLOW
        def denied? = @verdict == DENY
        def no_opinion? = @verdict == NO_OPINION
      end

      class Error < Security::Error; end
    end
  end
end
