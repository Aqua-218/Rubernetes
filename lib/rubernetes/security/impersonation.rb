# frozen_string_literal: true

require_relative "identity"
require_relative "authorization/attributes"

module Rubernetes
  module Security
    # Impersonation (k8s.io/apiserver/pkg/endpoints/filters/impersonation).
    #
    # A request may carry Impersonate-User / -Uid / -Group / -Extra-* headers
    # asking to act as another identity.  With ConstrainedImpersonation (Beta,
    # on by default in v1.36) the requester is tried against five modes in
    # order -- associated-node, arbitrary-node, serviceaccount, user-info and
    # legacy -- where each constrained mode needs both
    # `impersonate-on:<mode>:<verb>` on the request itself and
    # `impersonate:<mode>` on every impersonated identity, and the legacy mode
    # is the old unconstrained `impersonate` verb.  With the gate off only the
    # legacy filter runs.
    module Impersonation
      USER_HEADER = "impersonate-user"
      UID_HEADER = "impersonate-uid"
      GROUP_HEADER = "impersonate-group"
      EXTRA_PREFIX = "impersonate-extra-"

      AUTHENTICATION_GROUP = "authentication.k8s.io"
      NODE_USERNAME_PREFIX = "system:node:"
      NODE_NAME_EXTRA = "authentication.kubernetes.io/node-name"
      ASSOCIATED_NODE_KEYS_EXTRA = "authentication.kubernetes.io/associated-node-keys"
      LEGACY_VERB = "impersonate"
      MODES = %w[associated-node arbitrary-node serviceaccount user-info].freeze
      # manyAuthorizationChecksInLoop: at this many groups or extra values a
      # single wildcard check is tried before the per-value loop.
      MANY_CHECKS = 4
      CACHE_TTL = 10.0
      MODE_INDEX_CACHE_SIZE = 10_000

      DNS_LABEL = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/
      DNS_SUBDOMAIN = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/
      HTTP_PATH = %r{\A[A-Za-z0-9/\-._~%!$&'()*+,;=:]+\z}

      # The identity the headers ask for (user.DefaultInfo).
      Wanted = Struct.new(:name, :uid, :groups, :extra, keyword_init: true) do
        def only_username?
          uid.to_s.empty? && groups.empty? && extra.empty?
        end
      end

      Result = Struct.new(:user, :constraint)

      class BadRequest < Security::Error; end

      # responsewriters.ForbiddenStatusError: the Status message and details
      # name the impersonation check that failed, not the request.
      class Forbidden < Security::Error
        attr_reader :attributes, :reason

        def initialize(attributes, reason = nil)
          @attributes = attributes
          @reason = reason.to_s
          super(Impersonation.forbidden_status_message(attributes, @reason))
        end

        def details
          {"name" => @attributes.name, "group" => @attributes.api_group, "kind" => @attributes.resource}
            .reject { |_key, value| value.to_s.empty? }
        end
      end

      module_function

      # Cheap test run on every request: does any impersonation header exist?
      def requested?(request)
        headers = request.headers
        return false if headers.nil? || headers.empty?
        return true if headers.key?(USER_HEADER) || headers.key?(UID_HEADER) || headers.key?(GROUP_HEADER)

        headers.each_key.any? { |name| name.start_with?(EXTRA_PREFIX) }
      end

      # processImpersonationHeaders.  nil when impersonation is not asked for.
      def wanted_user(request, legacy: false)
        return nil unless requested?(request)

        name = header_values(request, USER_HEADER).first.to_s
        uid = header_values(request, UID_HEADER).first.to_s
        groups = header_values(request, GROUP_HEADER)
        extra = {}
        has_extra = false
        request.headers.each_key do |header|
          next unless header.start_with?(EXTRA_PREFIX)

          has_extra = true
          values = header_values(request, header)
          next if values.empty?

          key = unescape_extra_key(header.delete_prefix(EXTRA_PREFIX))
          (extra[key] ||= []).concat(values)
        end
        wanted = Wanted.new(name: name, uid: uid, groups: groups, extra: extra)
        if name.empty?
          return nil unless !uid.empty? || !groups.empty? || has_extra

          message = if legacy
                      "requested #{legacy_request_list(wanted)} without impersonating a user"
                    else
                      "requested #{go_default_info(wanted)} without impersonating a user name"
                    end
          raise BadRequest, message
        end
        wanted
      end

      # Every Impersonate-* header is removed once it has been honoured, so no
      # later handler (the streaming bridge, a proxied request) repeats it.
      def strip_headers(request)
        kept = request.headers.reject do |name, _value|
          name == USER_HEADER || name == UID_HEADER || name == GROUP_HEADER || name.start_with?(EXTRA_PREFIX)
        end
        request.with(headers: kept)
      end

      def header_values(request, name)
        values = request.respond_to?(:header_values) ? request.header_values(name) : Array(request.header(name))
        values.map(&:to_s)
      end

      # url.PathUnescape: a malformed escape keeps the key as written.
      def unescape_extra_key(key)
        return key unless key.include?("%")
        return key unless key.scan(/%(.{0,2})/m).all? { |(hex)| hex.match?(/\A\h\h\z/) }

        key.gsub(/%(\h\h)/) { Regexp.last_match(1).hex.chr }.dup.force_encoding(Encoding::UTF_8)
      end

      def node_username(username)
        return nil unless username.start_with?(NODE_USERNAME_PREFIX)

        name = username.delete_prefix(NODE_USERNAME_PREFIX)
        dns_subdomain?(name) ? name : nil
      end

      # serviceaccount.SplitUsername: [namespace, name] or nil.
      def service_account_username(username)
        return nil unless username.start_with?(UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX)

        parts = username.delete_prefix(UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX).split(":", -1)
        return nil unless parts.length == 2

        namespace, name = parts
        return nil unless namespace.length <= 63 && namespace.match?(DNS_LABEL)
        return nil unless dns_subdomain?(name)

        parts
      end

      def dns_subdomain?(value)
        value.length <= 253 && value.match?(DNS_SUBDOMAIN)
      end

      def service_account_groups(namespace)
        [UserInfo::SERVICE_ACCOUNT_GROUP_PREFIX, "#{UserInfo::SERVICE_ACCOUNT_GROUP_PREFIX}:#{namespace}"]
      end

      # Anonymous gets system:unauthenticated, everyone else
      # system:authenticated unless the groups already say unauthenticated.
      def with_implicit_group(groups, username)
        if username == UserInfo::ANONYMOUS_NAME
          groups.include?(UserInfo::ALL_UNAUTHENTICATED) ? groups : groups + [UserInfo::ALL_UNAUTHENTICATED]
        elsif groups.include?(UserInfo::ALL_UNAUTHENTICATED) || groups.include?(UserInfo::ALL_AUTHENTICATED)
          groups
        else
          groups + [UserInfo::ALL_AUTHENTICATED]
        end
      end

      def forbidden_status_message(attributes, reason)
        message = forbidden_message(attributes).gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
        message = "#{message}: #{reason}" unless reason.to_s.empty?
        group_resource = attributes.api_group.empty? ? attributes.resource.to_s : "#{attributes.resource}.#{attributes.api_group}"
        if attributes.name.empty?
          "#{group_resource} is forbidden: #{message}"
        else
          "#{group_resource} \"#{attributes.name}\" is forbidden: #{message}"
        end
      end

      def forbidden_message(attributes)
        username = attributes.user.respond_to?(:name) ? attributes.user.name : ""
        return "User #{username.inspect} cannot #{attributes.verb} path #{attributes.path.to_s.inspect}" unless attributes.resource_request?

        resource = attributes.resource_with_subresource
        if attributes.namespace.empty?
          "User #{username.inspect} cannot #{attributes.verb} resource #{resource.inspect} in API group " \
            "#{attributes.api_group.inspect} at the cluster scope"
        else
          "User #{username.inspect} cannot #{attributes.verb} resource #{resource.inspect} in API group " \
            "#{attributes.api_group.inspect} in the namespace #{attributes.namespace.inspect}"
        end
      end

      # checkAuthorization: anything but Allow is a Forbidden naming the
      # attributes that were checked.  No authorizer is AlwaysAllow.
      def check!(authorizer, attributes)
        return if authorizer.nil?

        decision = authorizer.authorize(attributes)
        return if decision.respond_to?(:allowed?) && decision.allowed?

        raise Forbidden.new(attributes, decision.respond_to?(:reason) ? decision.reason : nil)
      end

      def attributes_for(requestor, group, verb, resource, name)
        Authorization::Attributes.new(user: requestor, verb: verb, api_group: group, api_version: "v1",
                                      resource: resource, name: name, resource_request: true)
      end

      # user.DefaultInfo printed with %#v.
      def go_default_info(wanted)
        groups = wanted.groups.empty? ? "[]string(nil)" : "[]string{#{wanted.groups.map(&:inspect).join(", ")}}"
        extra = if wanted.extra.empty?
                  "map[string][]string(nil)"
                else
                  pairs = wanted.extra.sort.map { |key, values| "#{key.inspect}:[]string{#{values.map(&:inspect).join(", ")}}" }
                  "map[string][]string{#{pairs.join(", ")}}"
                end
        "&user.DefaultInfo{Name:#{wanted.name.inspect}, UID:#{wanted.uid.inspect}, Groups:#{groups}, Extra:#{extra}}"
      end

      # []v1.ObjectReference printed with %v (Kind Namespace Name UID
      # APIVersion ResourceVersion FieldPath).
      def legacy_request_list(wanted)
        references = wanted.groups.map { |group| ["Group", "", group, "", "", "", ""] }
        wanted.extra.each do |key, values|
          values.each { |value| references << ["UserExtra", "", value, "", "authentication.k8s.io/v1", "", key] }
        end
        references << ["UID", "", wanted.uid, "", "authentication.k8s.io/v1", "", ""] unless wanted.uid.empty?
        "[#{references.map { |fields| "{#{fields.join(" ")}}" }.join(" ")}]"
      end

      # k8s.io/apimachinery/pkg/util/cache.Expiring with a fixed TTL.
      class ExpiringCache
        PRUNE_AT = 4096

        def initialize(ttl: CACHE_TTL, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @ttl = ttl
          @clock = clock
          @entries = {}
          @mutex = Mutex.new
        end

        def get(key)
          @mutex.synchronize do
            entry = @entries[key]
            return nil unless entry
            return entry[0] if entry[1] > @clock.call

            @entries.delete(key)
            nil
          end
        end

        def set(key, value)
          @mutex.synchronize do
            now = @clock.call
            @entries.delete_if { |_key, entry| entry[1] <= now } if @entries.size >= PRUNE_AT
            @entries[key] = [value, now + @ttl]
          end
        end

        def size
          @mutex.synchronize { @entries.size }
        end
      end

      # k8s.io/utils/lru for the requester -> mode index cache.
      class LRU
        def initialize(capacity)
          @capacity = capacity
          @entries = {}
          @mutex = Mutex.new
        end

        def get(key)
          @mutex.synchronize do
            return nil unless @entries.key?(key)

            value = @entries.delete(key)
            @entries[key] = value
          end
        end

        def set(key, value)
          @mutex.synchronize do
            @entries.delete(key)
            @entries[key] = value
            @entries.delete(@entries.first[0]) while @entries.size > @capacity
          end
        end
      end

      # impersonationCacheKey: the wanted user, the requester and (for the
      # outer, per-request cache) every authorization attribute.  The key is
      # a frozen Array, hashed and compared by value.
      class CacheKey
        attr_reader :wanted, :attributes

        def initialize(wanted, attributes)
          @wanted = wanted
          @attributes = attributes
        end

        def key(skip_attributes)
          skip_attributes ? (@without ||= build(false)) : (@with ||= build(true))
        end

        private

        def build(with_attributes)
          parts = [user_tuple(@wanted), user_tuple(@attributes.user)]
          if with_attributes
            a = @attributes
            parts << [a.verb, a.namespace, a.resource.to_s, a.subresource, a.name, a.api_group, a.api_version,
                      a.resource_request?, a.path.to_s, a.field_selector.to_s, a.label_selector.to_s]
          end
          parts.freeze
        end

        def user_tuple(user)
          extra = user.extra || {}
          [user.name.to_s, user.uid.to_s, Array(user.groups).dup, extra.keys.sort.map { |key| [key, Array(extra[key]).dup] }]
        end
      end

      # impersonationModeState: the per-identity checks under one verb.
      class ModeState
        attr_reader :verb, :cache

        def initialize(authorizer, verb, constrained)
          @authorizer = authorizer
          @verb = verb
          @constrained = constrained
          @group = constrained ? AUTHENTICATION_GROUP : ""
          @constraint = constrained ? verb : ""
          @cache = ExpiringCache.new
        end

        def check(key, wanted, requestor)
          if @constrained && (cached = @cache.get(key.key(true)))
            return cached
          end

          groups = authorize_username!(requestor, wanted) || wanted.groups
          authorize_uid!(requestor, wanted.uid)
          authorize_groups!(requestor, wanted.groups)
          authorize_extra!(requestor, wanted.extra)
          user = UserInfo.new(name: wanted.name, uid: wanted.uid.to_s.empty? ? nil : wanted.uid,
                              groups: Impersonation.with_implicit_group(groups, wanted.name), extra: wanted.extra)
          result = Result.new(user, @constraint)
          @cache.set(key.key(true), result) if @constrained
          result
        end

        private

        # Returns the groups the impersonated user gets when the username
        # fixes them (a node, or a service account asked for with no groups).
        def authorize_username!(requestor, wanted)
          attributes = Impersonation.attributes_for(requestor, @group, @verb, "users", wanted.name)
          groups = nil
          if @constrained && (node = Impersonation.node_username(wanted.name))
            attributes = attributes.with(resource: "nodes", name: node)
            unless wanted.groups.empty?
              raise Forbidden.new(attributes, "when impersonating a node, cannot impersonate groups #{go_quoted(wanted.groups)}")
            end

            groups = [UserInfo::NODES_GROUP]
          end
          if (namespace, sa = Impersonation.service_account_username(wanted.name))
            attributes = attributes.with(resource: "serviceaccounts", namespace: namespace, name: sa)
            if @constrained && !wanted.groups.empty?
              raise Forbidden.new(attributes, "when impersonating a service account, cannot impersonate groups #{go_quoted(wanted.groups)}")
            end

            groups = Impersonation.service_account_groups(namespace) if wanted.groups.empty?
          end
          Impersonation.check!(@authorizer, attributes)
          groups
        end

        def authorize_uid!(requestor, uid)
          return if uid.to_s.empty?

          Impersonation.check!(@authorizer, Impersonation.attributes_for(requestor, AUTHENTICATION_GROUP, @verb, "uids", uid))
        end

        def authorize_groups!(requestor, groups)
          return if groups.empty?

          attributes = Impersonation.attributes_for(requestor, @group, @verb, "groups", "")
          if @constrained
            raise Forbidden.new(attributes, "impersonating the empty string group is not allowed") if groups.include?("")
            if groups.include?(UserInfo::MASTERS_GROUP)
              raise Forbidden.new(attributes.with(name: UserInfo::MASTERS_GROUP), "impersonating the system:masters group is not allowed")
            end
          end
          return if @constrained && groups.length >= MANY_CHECKS && allowed?(attributes.with(name: "*"))

          groups.each { |group| Impersonation.check!(@authorizer, attributes.with(name: group)) }
        end

        def authorize_extra!(requestor, extra)
          return if extra.empty?

          attributes = Impersonation.attributes_for(requestor, AUTHENTICATION_GROUP, @verb, "userextras", "")
          if @constrained && (problem = extra_problem(extra))
            raise Forbidden.new(attributes, problem)
          end
          return if @constrained && large_extra?(extra) && allowed?(attributes.with(subresource: "*", name: "*"))

          extra.each do |key, values|
            values.each { |value| Impersonation.check!(@authorizer, attributes.with(subresource: key, name: value)) }
          end
        end

        def allowed?(attributes)
          Impersonation.check!(@authorizer, attributes)
          true
        rescue Forbidden
          false
        end

        # validateExtra.
        def extra_problem(extra)
          extra.each do |key, values|
            return "impersonating the empty string key in extra is not allowed" if key.empty?

            invalid = domain_prefixed_path_error(key)
            return "impersonating an invalid key in extra is not allowed: #{invalid}" if invalid
            return "impersonating a non-lowercase key in extra is not allowed: #{key.inspect}" if key != key.downcase
            return "impersonating empty values in extra is not allowed" if values.empty?
            return "impersonating the empty string value in extra is not allowed" if values.include?("")
          end
          nil
        end

        # validation.IsDomainPrefixedPath at field path extra.key.
        def domain_prefixed_path_error(key)
          host, path = key.split("/", 2)
          if path.nil? || host.empty? || path.empty?
            return "extra.key: Invalid value: #{key.inspect}: must be a domain-prefixed path (such as \"acme.io/foo\")"
          end

          errors = []
          errors << "must be no more than 253 characters" if host.length > 253
          unless host.match?(DNS_SUBDOMAIN)
            errors << "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must " \
                      "start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is " \
                      "'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"
          end
          unless errors.empty?
            messages = errors.map { |error| "extra.key: Invalid value: #{host.inspect}: #{error}" }
            return messages.length == 1 ? messages.first : "[#{messages.join(", ")}]"
          end
          return nil if path.match?(HTTP_PATH)

          "extra.key: Invalid value: #{path.inspect}: Invalid path (regex used for validation is " \
            "'[A-Za-z0-9/\\-._~%!$&'()*+,;=:]+')"
        end

        def large_extra?(extra)
          extra.length >= MANY_CHECKS || extra.values.sum(&:length) >= MANY_CHECKS
        end

        # Go's %q of a []string.
        def go_quoted(values)
          "[#{values.map(&:inspect).join(" ")}]"
        end
      end

      # constrainedImpersonationModeState: a filter picks the requests the
      # mode is for, then impersonate-on:<mode>:<verb> on the request and the
      # identity checks under impersonate:<mode>.
      class ConstrainedMode
        attr_reader :mode, :state, :cache

        def initialize(authorizer, mode, &filter)
          @authorizer = authorizer
          @mode = mode
          @filter = filter
          @state = ModeState.new(authorizer, "impersonate:#{mode}", true)
          @cache = ExpiringCache.new
        end

        def check(key, wanted, attributes)
          requestor = attributes.user
          return nil unless @filter.call(wanted, requestor)

          cached = @cache.get(key.key(false))
          return cached if cached

          Impersonation.check!(@authorizer, attributes.with(verb: "impersonate-on:#{@mode}:#{attributes.verb}"))
          result = @state.check(key, wanted, requestor)
          @cache.set(key.key(false), result)
          result
        end
      end

      # associatedNodeImpersonationMode: a service account bound to a node (a
      # pod's token carries node-name) acting as that node.  Its authorizer
      # sees only the requester's extra KEYS and, for the identity check, the
      # node name "*", so one decision is cached for every node.
      class AssociatedNodeMode
        class ScopedAuthorizer
          def initialize(authorizer)
            @authorizer = authorizer
          end

          def authorize(attributes)
            name = attributes.verb == "impersonate:associated-node" ? "*" : attributes.name
            @authorizer.authorize(attributes.with(user: AssociatedNodeMode.scoped_user(attributes.user), name: name))
          end
        end

        attr_reader :inner

        def initialize(authorizer)
          @inner = ConstrainedMode.new(authorizer && ScopedAuthorizer.new(authorizer), "associated-node") do |wanted, requestor|
            wanted.only_username? && AssociatedNodeMode.associated?(requestor, wanted.name)
          end
        end

        def self.scoped_user(user)
          UserInfo.new(name: user.name, uid: user.uid, groups: user.groups, extra: {ASSOCIATED_NODE_KEYS_EXTRA => user.extra.keys.sort})
        end

        def self.associated?(requestor, username)
          node = Impersonation.node_username(username)
          return false unless node
          return false unless Impersonation.service_account_username(requestor.name)

          values = requestor.extra[NODE_NAME_EXTRA]
          values.is_a?(Array) && values.length == 1 && values.first == node
        end

        def check(_key, wanted, attributes)
          key = CacheKey.new(Wanted.new(name: "#{NODE_USERNAME_PREFIX}*", uid: "", groups: [], extra: {}),
                             attributes.with(user: AssociatedNodeMode.scoped_user(attributes.user)))
          result = @inner.check(key, wanted, attributes)
          return nil unless result

          # The cached user may carry another node's name.
          user = result.user
          Result.new(UserInfo.new(name: wanted.name, uid: user.uid, groups: user.groups, extra: user.extra), result.constraint)
        end
      end

      # legacyImpersonationMode as the last constrained-tracker mode.
      class LegacyMode
        attr_reader :state

        def initialize(authorizer)
          @state = ModeState.new(authorizer, LEGACY_VERB, false)
        end

        def check(key, wanted, attributes)
          @state.check(key, wanted, attributes.user)
        end
      end

      # impersonationModesTracker.
      class Tracker
        attr_reader :modes

        def initialize(authorizer)
          @modes = [
            AssociatedNodeMode.new(authorizer),
            ConstrainedMode.new(authorizer, "arbitrary-node") do |wanted, _requestor|
              wanted.only_username? && !Impersonation.node_username(wanted.name).nil?
            end,
            ConstrainedMode.new(authorizer, "serviceaccount") do |wanted, _requestor|
              wanted.only_username? && !Impersonation.service_account_username(wanted.name).nil?
            end,
            ConstrainedMode.new(authorizer, "user-info") do |wanted, _requestor|
              Impersonation.node_username(wanted.name).nil? && Impersonation.service_account_username(wanted.name).nil?
            end,
            LegacyMode.new(authorizer)
          ]
          @index = LRU.new(MODE_INDEX_CACHE_SIZE)
        end

        def impersonate(wanted, attributes)
          key = CacheKey.new(wanted, attributes)
          first_error = nil
          cached_index = @index.get(attributes.user.name)
          if cached_index
            begin
              result = @modes[cached_index].check(key, wanted, attributes)
              return result if result
            rescue Forbidden => error
              first_error = error
            end
          end
          @modes.each_with_index do |mode, index|
            next if index == cached_index

            begin
              result = mode.check(key, wanted, attributes)
            rescue Forbidden => error
              first_error ||= error
              next
            end
            next unless result

            @index.set(attributes.user.name, index)
            return result
          end
          raise first_error if first_error

          raise Forbidden.new(attributes, "all impersonation modes failed")
        end
      end

      # WithImpersonation (ConstrainedImpersonation off): one `impersonate`
      # check per requested identity -- user, groups, extras, uid.
      class LegacyFilter
        def initialize(authorizer)
          @authorizer = authorizer
        end

        def impersonate(wanted, attributes)
          requestor = attributes.user
          groups = []
          if (namespace, name = Impersonation.service_account_username(wanted.name))
            Impersonation.check!(@authorizer, Impersonation.attributes_for(requestor, "", LEGACY_VERB, "serviceaccounts", name)
                                                .with(namespace: namespace))
            groups = Impersonation.service_account_groups(namespace) if wanted.groups.empty?
          else
            Impersonation.check!(@authorizer, Impersonation.attributes_for(requestor, "", LEGACY_VERB, "users", wanted.name))
          end
          wanted.groups.each do |group|
            Impersonation.check!(@authorizer, Impersonation.attributes_for(requestor, "", LEGACY_VERB, "groups", group))
            groups += [group]
          end
          wanted.extra.each do |key, values|
            values.each do |value|
              attributes = Impersonation.attributes_for(requestor, AUTHENTICATION_GROUP, LEGACY_VERB, "userextras", value)
              Impersonation.check!(@authorizer, attributes.with(subresource: key))
            end
          end
          unless wanted.uid.empty?
            Impersonation.check!(@authorizer, Impersonation.attributes_for(requestor, AUTHENTICATION_GROUP, LEGACY_VERB, "uids", wanted.uid))
          end
          user = UserInfo.new(name: wanted.name, uid: wanted.uid.empty? ? nil : wanted.uid,
                              groups: Impersonation.with_implicit_group(groups, wanted.name), extra: wanted.extra)
          Result.new(user, "")
        end
      end

      # The filter the security pipeline runs: parse, pick the implementation
      # for the feature gate, record apiserver_impersonation_* metrics.
      class Filter
        ATTEMPTS = "apiserver_impersonation_attempts_total"
        ATTEMPT_SECONDS = "apiserver_impersonation_attempts_duration_seconds"
        AUTHORIZATIONS = "apiserver_impersonation_authorization_attempts_total"
        AUTHORIZATION_SECONDS = "apiserver_impersonation_authorization_attempts_duration_seconds"
        BUCKETS = (0...15).map { |exponent| 0.001 * (2**exponent) }.freeze

        # metricsAuthorizer: every check the modes make, labelled by mode.
        class MeteredAuthorizer
          attr_accessor :metrics

          def initialize(authorizer)
            @authorizer = authorizer
          end

          def authorize(attributes)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            decision = @authorizer.authorize(attributes)
            metrics = @metrics
            if metrics
              labels = {"mode" => Filter.mode_from_verb(attributes.verb), "decision" => decision.allowed? ? "allowed" : "denied"}
              metrics.increment(AUTHORIZATIONS, labels)
              metrics.observe(AUTHORIZATION_SECONDS, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
            end
            decision
          end
        end

        attr_reader :constrained

        def initialize(authorizer, constrained: true)
          @constrained = constrained
          @metered = authorizer && MeteredAuthorizer.new(authorizer)
          @implementation = constrained ? Tracker.new(@metered) : LegacyFilter.new(authorizer)
          @metrics = nil
        end

        # The metrics exist only with the gate on, as upstream registers them
        # in WithConstrainedImpersonation.
        def metrics=(metrics)
          return unless @constrained && metrics

          metrics.register(ATTEMPTS, type: :counter, help: "Total number of impersonation attempts split by mode and decision.")
          metrics.register(ATTEMPT_SECONDS, type: :histogram, buckets: BUCKETS,
                                            help: "Latency of impersonation attempts in seconds split by mode and decision.")
          metrics.register(AUTHORIZATIONS, type: :counter,
                                           help: "Total number of authorization checks made by the impersonation handler split by mode and decision.")
          metrics.register(AUTHORIZATION_SECONDS, type: :histogram, buckets: BUCKETS,
                                                  help: "Latency of authorization checks made by the impersonation handler in seconds " \
                                                        "split by mode and decision.")
          @metered.metrics = metrics if @metered
          @metrics = metrics
        end

        def wanted_user(request)
          Impersonation.wanted_user(request, legacy: !@constrained)
        end

        # Result for the requester's own request attributes, or Forbidden.
        def impersonate(wanted, attributes)
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = @implementation.impersonate(wanted, attributes)
          record("allowed", Filter.mode_from_constraint(result.constraint), started)
          result
        rescue Forbidden
          record("denied", "", started)
          raise
        end

        def self.mode_from_constraint(constraint)
          constraint.to_s.empty? ? "legacy" : mode_from_verb(constraint)
        end

        def self.mode_from_verb(verb)
          return "legacy" if verb == LEGACY_VERB

          MODES.each do |mode|
            return mode if verb == "impersonate:#{mode}" || verb.start_with?("impersonate-on:#{mode}:")
          end
          "unknown"
        end

        private

        def record(decision, mode, started)
          metrics = @metrics
          return unless metrics

          labels = {"mode" => mode, "decision" => decision}
          metrics.increment(ATTEMPTS, labels)
          metrics.observe(ATTEMPT_SECONDS, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        end
      end
    end
  end
end
