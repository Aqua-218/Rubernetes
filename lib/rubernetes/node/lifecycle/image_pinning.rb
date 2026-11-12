# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Resolves and pins every image of a Pod before any other effect, and
      # reports each pull the way kubelet's image manager does.
      module ImagePinning
        private

        # Resolve every container image before the first volume, filesystem,
        # network, or runtime effect. The resolver is an explicit dependency so
        # pure tests never perform registry I/O accidentally.
        def pin_images(pod, record)
          definitions = container_image_definitions(pod)
          return if definitions.empty?

          references = definitions.filter_map { |_category, _index, definition| Helpers.key(definition, "image", nil) }
          if @image_resolver.nil?
            if native_runtime? && references.any? { |reference| !reference.to_s.empty? }
              raise LifecycleError, "image resolver is required before starting a Native Pod"
            end

            return
          end

          keyring = image_keyring(pod)
          definitions.each do |_category, _index, definition|
            reference = Helpers.key(definition, "image", nil)
            raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect} has no image" if reference.to_s.empty?
          end
          pin_container_images(record, definitions, pull_images(record, definitions, keyring))
          pin_volume_images(pod, record, keyring)
          digests = record[:images].map { |image| image_to_hash(image).fetch("digest") }.uniq.sort
          raise LifecycleError, "image resolver returned no pinned digest" if digests.empty?

          record[:image_digest] = "sha256:#{::Digest::SHA256.hexdigest(JSON.generate(digests))}"
          event(record, "image.pinned", digests: digests, aggregate_digest: record[:image_digest])
        end

        # [category, index, container definition] for every init and app
        # container, in start order.
        def container_image_definitions(pod)
          definitions = []
          spec = Helpers.key(pod, "spec", {})
          Array(Helpers.key(spec, "initContainers", [])).each_with_index do |definition, index|
            definitions << ["init", index, Helpers.string_keys(definition)]
          end
          Array(Helpers.key(spec, "containers", [])).each_with_index do |definition, index|
            definitions << ["app", index, Helpers.string_keys(definition)]
          end
          definitions
        end

        # imagePullPolicy per image: Always when any container of it asks,
        # Never only when all of them do.
        def image_pull_policies(definitions)
          definitions.group_by { |_category, _index, definition| Helpers.key(definition, "image", nil).to_s }
            .transform_values do |entries|
            values = entries.map { |_category, _index, definition| Helpers.key(definition, "imagePullPolicy", nil).to_s }
            if values.include?("Always") then "Always"
            elsif !values.empty? && values.all?("Never") then "Never"
            elsif values.include?("IfNotPresent") then "IfNotPresent"
            end
          end
        end

        # Pulls the Pod's distinct images and answers them by reference, in
        # start order; the first failed pull is raised once every pull ended.
        def pull_images(record, definitions, keyring)
          # A Pod's distinct images are pulled side by side (kubelet's parallel
          # image pulls); one after the other, a DNS spec's Pod waited for
          # agnhost and then for jessie-dnsutils.
          pending = definitions.each_with_object({}) do |(_category, _index, definition), unique|
            unique[Helpers.key(definition, "image", nil).to_s] ||= Helpers.key(definition, "name", nil)
          end
          policies = image_pull_policies(definitions)
          # kubelet's image manager reports each image as it gets there: Pulling
          # when a pull starts, then per container Pulled with the pull's time
          # and size, or "already present" (see image_events).  A resolver that
          # cannot tell pulls apart only has Pulling, up front.
          reports = pending.keys.to_h { |cache_key| [cache_key, {}] }
          reporting = resolver_accepts?(:on_pull)
          lock = Mutex.new
          pending.each { |cache_key, name| event(record, "image.resolve", reference: cache_key, name: name) } unless reporting
          pulls = pending.keys.map do |cache_key|
            reporter = reporting ? image_reporter(record, cache_key, pending[cache_key], reports[cache_key], lock) : nil
            [cache_key, Thread.new { resolve_image(cache_key, keyring, policies[cache_key], reporter) }]
          end
          cache = {}
          failure = nil
          pulls.each do |cache_key, thread|
            outcome = thread.value
            if outcome.is_a?(Exception)
              failure ||= [cache_key, outcome]
              next
            end
            cache[cache_key] = outcome
          end
          image_events(record, definitions, reports, failure) if reporting
          raise_pull_failure(record, failure) if failure
          cache
        end

        def raise_pull_failure(record, failure)
          cache_key, error = failure
          raise error if error.is_a?(LifecycleError)

          if defined?(::Rubernetes::Image::NeverPullError) && error.is_a?(::Rubernetes::Image::NeverPullError)
            # ErrImageNeverPull: pull policy Never and the image is not here.
            record[:reason] = "ErrImageNeverPull"
            raise LifecycleError, error.message
          end
          # kubelet: a pull that fails leaves the container Waiting with
          # reason ErrImagePull (ImagePullBackOff while the retry waits)
          # and the Pod Pending; e2e reads exactly that reason.
          record[:reason] = "ErrImagePull"
          raise LifecycleError, "Failed to pull image #{cache_key.inspect}: #{Helpers.failure_message(error)}"
        end

        # The pulled images become the record's, and each container is told
        # which one it runs.
        def pin_container_images(record, definitions, images)
          images.each do |cache_key, resolved|
            raise LifecycleError, "image resolver returned no image for #{cache_key.inspect}" if resolved.nil?

            record[:images] << resolved
          end
          definitions.each do |category, index, definition|
            reference = Helpers.key(definition, "image", nil)
            image_hash = image_to_hash(images.fetch(reference.to_s), reference)
            record[:image_by_container][image_key(category, index)] = image_hash
          end
        end

        # An image volume (spec.volumes[].image) is pulled and pinned like a
        # container image; its unpacked rootfs is what the volume mounts,
        # read-only.  It is kept apart from record[:images], which are the
        # containers' own overlay lowerdirs.
        def pin_volume_images(pod, record, keyring)
          Array(Helpers.key(Helpers.key(pod, "spec", {}), "volumes", [])).each do |volume|
            entry = Helpers.string_keys(volume)
            source = Helpers.key(entry, "image", nil)
            next unless source.is_a?(Hash)

            reference = Helpers.key(source, "reference", nil).to_s
            raise LifecycleError, "image volume #{Helpers.key(entry, "name", "").inspect} has no reference" if reference.empty?
            next if record[:volume_images].key?(reference)

            resolved = ensure_image(record, reference, nil, keyring, Helpers.key(source, "pullPolicy", nil),
                                    volume: Helpers.key(entry, "name", nil))
            raise LifecycleError, "image resolver returned no image for #{reference.inspect}" if resolved.nil?

            record[:volume_image_handles] << resolved
            record[:volume_images][reference] = image_to_hash(resolved, reference)
          end
        end

        # One image, for pin_images' pull threads: the resolved image, or the
        # exception the pull raised (re-raised by the caller in order).
        def resolve_image(reference, keyring, pull_policy = nil, on_pull = nil)
          resolve_with_keyring(reference, keyring, pull_policy, on_pull)
        rescue StandardError => error
          error
        end

        # KubeletEnsureSecretPulledImages: the resolver also learns which Secret
        # the credential came from and every Secret of the Pod for the image,
        # when it takes them.
        def resolve_with_keyring(reference, keyring, pull_policy = nil, on_pull = nil)
          credential = keyring&.lookup(reference)
          keywords = {}
          keywords[:on_pull] = on_pull if on_pull && resolver_accepts?(:on_pull)
          keywords[:credentials] = credential.to_h if credential
          keywords[:pull_policy] = pull_policy.to_s unless pull_policy.to_s.empty?
          if resolver_accepts?(:pull_secret)
            keywords[:pull_secret] = credential.pull_secret if credential&.pull_secret
            keywords[:pod_credentials] = lambda do
              secrets = keyring ? keyring.lookup_all(reference).filter_map(&:pull_secret) : []
              account = keyring&.service_account_for(reference)
              [secrets.reject { |secret| secret[:service_account] }, account]
            end
          end
          keywords.empty? ? invoke(@image_resolver, :resolve, reference) : invoke(@image_resolver, :resolve, reference, **keywords)
        end

        def resolver_accepts?(keyword)
          @resolver_keywords ||= begin
            parameters = @image_resolver.method(:resolve).parameters
            if parameters.any? { |kind, _| kind == :keyrest }
              :any
            else
              parameters.filter_map do |kind, name|
                name if %i[key keyreq].include?(kind)
              end
            end
          rescue NameError
            # No resolver, or one without #resolve: it takes no keywords.
            []
          end
          @resolver_keywords == :any ? false : @resolver_keywords.include?(keyword)
        end

        # One image outside the Pod's start sweep (an ephemeral container, an
        # image volume), with the same events.
        def ensure_image(record, reference, name, keyring, policy, volume: nil)
          unless resolver_accepts?(:on_pull)
            event(record, "image.resolve", **{reference: reference, name: name, volume: volume}.compact)
            return resolve_with_keyring(reference, keyring, policy)
          end

          report = {}
          outcome = resolve_image(reference, keyring, policy, image_reporter(record, reference, name, report, Mutex.new))
          definition = {"image" => reference, "name" => name, "imagePullPolicy" => policy}.compact
          image_events(record, [[nil, nil, definition]], {reference => report}, outcome.is_a?(Exception) ? [reference, outcome] : nil)
          raise outcome if outcome.is_a?(Exception)

          outcome
        end

        # One image's pull as the resolver reports it (Image::Resolver#resolve
        # on_pull), from its pull thread.
        def image_reporter(record, reference, name, report, lock)
          lambda do |stage, *details|
            case stage
            when :present then report[:present] = details.first
            when :required then report[:required] = true
            when :start
              report[:pulled] = true
              lock.synchronize { event(record, "image.resolve", reference: reference, name: name) }
            when :done
              report[:seconds], report[:size] = details
              report[:finished_at] = Helpers.now(@clock).iso8601(6)
            when :failed then report[:error] = details.first
            end
          end
        end

        # EnsureImageExists, container by container in start order: the first
        # container of an image reports its pull (Pulled, Failed or
        # ErrImageNeverPull), every later one finds it already present.  It
        # stops at the container whose image failed, as kubelet does, and
        # counts kubelet_image_manager_ensure_image_requests_total.
        def image_events(record, definitions, reports, failure)
          failed, error = failure
          never = defined?(::Rubernetes::Image::NeverPullError) && error.is_a?(::Rubernetes::Image::NeverPullError)
          seen = {}
          definitions.each do |_category, _index, definition|
            reference = Helpers.key(definition, "image", nil).to_s
            name = Helpers.key(definition, "name", nil)
            policy = Helpers.key(definition, "imagePullPolicy", nil).to_s
            report = seen.key?(reference) ? {present: true} : reports.fetch(reference, {})
            seen[reference] = true
            if reference == failed && never
              # policy Never: not here, or not usable by this Pod.
              required = report[:required] ? "true" : "unknown"
              event(record, "image.never_pull", reference: reference, name: name, policy: policy, present: report[:present],
                                                required: required)
              break
            elsif reference == failed
              # Only a pull that ran reports Failed; credentials that could not
              # be read end EnsureImageExists before it.
              if report[:pulled]
                event(record, "image.pull_failed", reference: reference, name: name, policy: policy, present: report[:present],
                                                   error: (report[:error] || error).message.to_s)
              end
              break
            elsif report[:pulled]
              event(record, "image.pulled", reference: reference, name: name, policy: policy, present: report[:present],
                                            seconds: report[:seconds].to_f, size: report[:size].to_i, finished_at: report[:finished_at])
            else
              event(record, "image.present", reference: reference, name: name, policy: policy)
            end
          end
        end

        # imagePullSecrets (Pod + ServiceAccount) become the registry keyring
        # for this Pod's pulls; without a resource reader there is nothing to
        # read them from and pulls stay anonymous.
        def image_keyring(pod)
          return nil unless @resource_reader || @credential_providers

          keyring = ImageCredentials.for_pod(pod, reader: @resource_reader, providers: @credential_providers)
          keyring.empty? ? nil : keyring
        rescue StandardError => error
          raise LifecycleError, "imagePullSecrets could not be read: #{Helpers.failure_message(error)}"
        end

        def image_key(category, index)
          "#{category}:#{index}"
        end

        def image_to_hash(image, fallback_reference = nil)
          value = hash_convertible?(image) ? image.to_h : image
          hash = Helpers.string_keys(value)
          raise LifecycleError, "image resolver must return a hash-like image" unless hash.is_a?(Hash)

          digest = Helpers.key(hash, "digest", nil)
          raise LifecycleError, "image resolver returned an invalid pinned digest" unless digest.to_s.match?(/\Asha256:[0-9a-fA-F]{64}\z/)

          hash["digest"] = digest.to_s.downcase
          unless fallback_reference.nil?
            hash["reference"] ||= fallback_reference.to_s
            hash["requested_reference"] ||= fallback_reference.to_s
          end
          hash
        end

        # An ephemeral container is added after the Pod is already running, so its
        # image is pinned here rather than in the initial pin_images sweep.
        def pin_ephemeral_image(pod, record, definition, index)
          return if record[:image_by_container].key?(image_key("ephemeral", index))

          reference = Helpers.key(definition, "image", nil)
          raise LifecycleError, "ephemeral container #{Helpers.key(definition, "name", "").inspect} has no image" if reference.to_s.empty?
          return if @image_resolver.nil?

          resolved = ensure_image(record, reference.to_s, Helpers.key(definition, "name", nil), image_keyring(pod),
                                  Helpers.key(definition, "imagePullPolicy", nil))
          raise LifecycleError, "image resolver returned no image for #{reference.to_s.inspect}" if resolved.nil?

          record[:images] << resolved
          record[:image_by_container][image_key("ephemeral", index)] = image_to_hash(resolved, reference)
        end
      end
    end
  end
end
