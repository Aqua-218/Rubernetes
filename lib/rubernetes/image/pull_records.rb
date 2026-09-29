# frozen_string_literal: true

module Rubernetes
  module Image
    # KubeletEnsureSecretPulledImages (Beta, on in v1.36;
    # pkg/kubelet/images/pullmanager): which credentials pulled each image, so
    # a Pod reusing an image already on the node must hold credentials that
    # could pull it, instead of borrowing another Pod's secret.
    #
    # A record maps an image (by its digest, the imageRef) to, per repository
    # (the image name without tag or digest), the credentials that pulled it:
    # node-wide / anonymous access (NodePodsAccessible), Kubernetes Secrets
    # (coordinates plus a hash of the auth config) or ServiceAccounts.
    #
    # Records live in memory: an unpacked image never outlives the agent here
    # (staging directories of a dead agent are reclaimed at start), so every
    # image in the cache was pulled by this process and there are no pull
    # intents to recover.
    class PullRecords
      NEVER_VERIFY = "NeverVerify"
      NEVER_VERIFY_PRELOADED = "NeverVerifyPreloadedImages"
      NEVER_VERIFY_ALLOWLISTED = "NeverVerifyAllowlistedImages"
      ALWAYS_VERIFY = "AlwaysVerify"
      POLICIES = [NEVER_VERIFY, NEVER_VERIFY_PRELOADED, NEVER_VERIFY_ALLOWLISTED, ALWAYS_VERIFY].freeze
      # writeRecordWhileMatchingLimit.
      MATCH_WRITE_LIMIT = 100

      # One pull's credentials.  +secrets+: [{uid:, namespace:, name:, hash:}];
      # +service_accounts+: [{uid:, namespace:, name:}].
      Credentials = Struct.new(:node_accessible, :secrets, :service_accounts, keyword_init: true) do
        def self.node = new(node_accessible: true, secrets: [], service_accounts: [])

        def self.secret(uid:, namespace:, name:, hash:)
          new(node_accessible: false, secrets: [{uid: uid.to_s, namespace: namespace.to_s, name: name.to_s, hash: hash.to_s}],
              service_accounts: [])
        end

        def empty? = !node_accessible && secrets.empty? && service_accounts.empty?
      end

      class InvalidPolicy < ArgumentError; end

      attr_reader :policy

      def initialize(policy: NEVER_VERIFY_PRELOADED, allowlist: [], clock: -> { Time.now.utc })
        @policy = policy.to_s
        raise InvalidPolicy, "unknown image pull credential verification policy: #{@policy}" unless POLICIES.include?(@policy)

        @exact, @prefixes = self.class.parse_allowlist(allowlist)
        @clock = clock
        @records = {}
        @mutex = Mutex.new
      end

      # getAllowlistImagePattern: "registry/path" exactly, or a "registry/path/*"
      # prefix; no tags, digests or other wildcards.
      def self.parse_allowlist(patterns)
        exact = {}
        prefixes = []
        Array(patterns).each do |pattern|
          pattern = pattern.to_s
          raise InvalidPolicy, "leading/trailing spaces are not allowed: #{pattern}" if pattern != pattern.strip

          wildcard = pattern.end_with?("/*")
          trimmed = wildcard ? pattern.delete_suffix("*") : pattern
          raise InvalidPolicy, "the supplied pattern is too short: #{pattern}" if trimmed.empty?
          if trimmed.include?("*")
            raise InvalidPolicy, "not a valid wildcard pattern, only patterns ending with '/*' are allowed: #{pattern}"
          end

          if wildcard
            raise InvalidPolicy, "at least registry hostname is required" if trimmed.length == 1

            prefixes << trimmed
          else
            if trim_tag_digest(pattern) != pattern
              raise InvalidPolicy, "neither tag nor digest is accepted in an image reference: #{pattern}"
            end

            exact[trimmed] = true
          end
        end
        [exact, prefixes.freeze]
      end

      # trimImageTagDigest: the image name without its ":tag" (after the
      # last "/") or "@digest".
      def self.trim_tag_digest(image)
        name = image.to_s.split("@", 2).first
        slash = name.rindex("/")
        colon = name.rindex(":")
        colon && (slash.nil? || colon > slash) ? name[0...colon] : name
      end

      # RequireCredentialVerificationForImage.  Every image this resolver
      # serves from its cache was pulled by the kubelet (no preloaded images).
      def verification_required?(repository, pulled_by_kubelet: true)
        case @policy
        when NEVER_VERIFY then false
        when NEVER_VERIFY_PRELOADED then pulled_by_kubelet
        when NEVER_VERIFY_ALLOWLISTED then !(@exact[repository] || @prefixes.any? { |prefix| repository.start_with?(prefix) })
        else true
        end
      end

      # RecordImagePulled / writePulledRecordIfChanged.
      def record_pulled(repository, image_ref, credentials)
        return if image_ref.to_s.empty?

        @mutex.synchronize do
          record = (@records[image_ref.to_s] ||= {updated: @clock.call, mapping: {}})
          merged, changed = merge(record[:mapping][repository], credentials || Credentials.node)
          next unless changed

          record[:mapping][repository] = merged
          record[:updated] = @clock.call
        end
      end

      # MustAttemptImagePull.  +pod_credentials+ is only called when the
      # record holds Secrets or ServiceAccounts: -> [[secret...], service_account]
      # with the Pod's own keyring entries for the repository.
      def must_attempt_pull?(repository, image_ref, pod_credentials)
        return true if image_ref.to_s.empty?

        cached = @mutex.synchronize { @records.dig(image_ref.to_s, :mapping, repository) }
        return false unless verification_required?(repository, pulled_by_kubelet: true)
        return true if cached.nil?
        return false if cached.node_accessible
        return true if cached.secrets.empty? && cached.service_accounts.empty?

        secrets, service_account = pod_credentials.respond_to?(:call) ? pod_credentials.call : [[], nil]
        Array(secrets).each do |secret|
          cached.secrets.each do |known|
            hash_match = !known[:hash].empty? && secret[:hash].to_s == known[:hash]
            same_secret = secret[:uid].to_s == known[:uid] && secret[:namespace].to_s == known[:namespace] &&
                          secret[:name].to_s == known[:name]
            if hash_match
              # The same credential in another Secret: remember that Secret.
              remember(repository, image_ref, secret) if !same_secret && cached.secrets.length < MATCH_WRITE_LIMIT
              return false
            end
            # This Secret, rotated: its new hash is recorded and it may use
            # the image (only while the record is small, as upstream).
            if same_secret && cached.secrets.length < MATCH_WRITE_LIMIT
              remember(repository, image_ref, secret)
              return false
            end
          end
        end
        return false if service_account && cached.service_accounts.include?(service_account)

        true
      end

      # PruneUnknownRecords: forget images no longer on the node.
      def prune(keep_image_refs, before: nil)
        keep = keep_image_refs.map(&:to_s)
        @mutex.synchronize do
          @records.delete_if { |image_ref, record| !keep.include?(image_ref) && (before.nil? || record[:updated] < before) }
        end
      end

      def forget(image_ref)
        @mutex.synchronize { @records.delete(image_ref.to_s) }
      end

      def record(image_ref)
        @mutex.synchronize { @records[image_ref.to_s]&.dup }
      end

      private

      def remember(repository, image_ref, secret)
        record_pulled(repository, image_ref, Credentials.secret(uid: secret[:uid], namespace: secret[:namespace],
                                                                name: secret[:name], hash: secret[:hash]))
      end

      # pulledRecordMergeNewCreds.
      def merge(existing, incoming)
        return [incoming, true] if existing.nil?
        return [existing, false] if incoming.empty? || existing.node_accessible
        return [Credentials.node, true] if incoming.node_accessible

        if !incoming.secrets.empty?
          secrets = existing.secrets.to_h { |secret| [secret.values_at(:uid, :namespace, :name), secret[:hash]] }
          changed = false
          incoming.secrets.each do |secret|
            key = secret.values_at(:uid, :namespace, :name)
            next if secrets[key] == secret[:hash]

            secrets[key] = secret[:hash]
            changed = true
          end
          return [existing, false] unless changed

          list = secrets.map { |(uid, namespace, name), hash| {uid: uid, namespace: namespace, name: name, hash: hash} }
                        .sort_by { |secret| secret.values_at(:namespace, :name, :uid) }
          [Credentials.new(node_accessible: false, secrets: list, service_accounts: existing.service_accounts), true]
        else
          accounts = (existing.service_accounts | incoming.service_accounts).sort_by { |account| account.values_at(:namespace, :name, :uid) }
          return [existing, false] if accounts == existing.service_accounts

          [Credentials.new(node_accessible: false, secrets: existing.secrets, service_accounts: accounts), true]
        end
      end
    end
  end
end
