# frozen_string_literal: true

require "json"

module Rubernetes
  module API
    module CRD
      # The routes in apiextensions-apiserver's controller/openapi/builder.
      # The metav1 query parameters are shared with built-in resources.
      class OpenAPIRoutes
        CORE_V3 = "v3/api/v1.json"
        POD_COLLECTION = "/api/v1/namespaces/{namespace}/pods"
        POD_ITEM = "#{POD_COLLECTION}/{name}".freeze
        TITLE = "Kubernetes CRD Swagger"
        META = "io.k8s.apimachinery.pkg.apis.meta.v1"
        DELETE_OPTIONS = "#{META}.DeleteOptions".freeze
        SCALE = "io.k8s.api.autoscaling.v1.Scale"
        GVK = "x-kubernetes-group-version-kind"
        EXTERNAL_SCHEME_GROUPS = %w[admission.k8s.io apiextensions.k8s.io apiregistration.k8s.io imagepolicy.k8s.io].freeze
        COLLECTION = %i[list create delete_collection].freeze
        ITEM = %i[read replace delete patch].freeze
        SUBRESOURCE = %i[read replace patch].freeze
        MEDIA = %w[application/json application/yaml].freeze
        PATCH_MEDIA = %w[application/apply-patch+yaml application/json-patch+json application/merge-patch+json].freeze
        RESPONSE_DESCRIPTIONS = {"200" => "OK", "201" => "Created", "202" => "Accepted", "401" => "Unauthorized"}.freeze
        OPERATIONS = {
          list: ["get", "list", "list", %w[200]],
          create: ["post", "post", "create", %w[200 201 202]],
          delete_collection: ["delete", "deletecollection", "delete", %w[200]],
          read: ["get", "get", "read", %w[200]],
          replace: ["put", "put", "replace", %w[200 201]],
          delete: ["delete", "delete", "delete", %w[200 202]],
          patch: ["patch", "patch", "patch", %w[200]]
        }.freeze

        # CRD builder uses client-go/kubernetes/scheme, which registers the
        # versioned DeleteOptions aliases for the typed Kubernetes client.
        # The aggregate built-in document has that schema's full API scheme.
        def self.add_delete_options_gvks(document)
          return unless document.dig("info", "title") == TITLE

          schema = document.dig("components", "schemas", DELETE_OPTIONS)
          return unless schema

          aggregate = yield
          aliases = aggregate&.dig("definitions", DELETE_OPTIONS, GVK)
          schema[GVK] = aliases.reject { |gvk| EXTERNAL_SCHEME_GROUPS.include?(gvk.fetch("group")) } if aliases
        end

        def initialize(repository, gvk:, plural:, definition_name:, list_name:, namespaced:, subresources:)
          @gvk = gvk
          @kind = gvk.fetch("kind")
          group = gvk.fetch("group")
          version = gvk.fetch("version")
          @plural = plural
          @base = "/apis/#{group}/#{version}"
          @definition_name = definition_name
          @list_name = list_name
          @namespaced = namespaced
          @subresources = subresources || {}
          group_name = group.delete_suffix(".k8s.io")
          @id_scope = identifier(group_name, upper: true) + identifier(version, upper: true)
          @tag = "#{identifier(group_name)}_#{identifier(version)}"
          @options, @common = parameters(repository)
        end

        def paths
          cluster_path = "#{@base}/#{@plural}"
          collection = @namespaced ? "#{@base}/namespaces/{namespace}/#{@plural}" : cluster_path
          item = "#{collection}/{name}"
          result = {collection => path_item(COLLECTION), item => path_item(ITEM, named: true)}
          %w[status scale].each do |subresource|
            next unless @subresources[subresource]

            result["#{item}/#{subresource}"] = path_item(SUBRESOURCE, named: true, subresource: subresource)
          end
          result[cluster_path] = path_item([:list], all_namespaces: true) if @namespaced
          result
        end

        private

        def parameters(repository)
          core = repository.static_document(CORE_V3)
          unless core&.dig("paths", POD_COLLECTION, "get")
            # A custom OpenAPI directory can override served built-ins. The
            # CRD builder still uses the bundled metav1 parameter contract.
            core = JSON.parse(File.binread(File.join(OpenAPIRepository::DEFAULT_ROOT, CORE_V3)), max_nesting: 512)
          end
          collection, item = core.fetch("paths").values_at(POD_COLLECTION, POD_ITEM)
          common = item.fetch("parameters").to_h { |option| [option.fetch("name"), option] }
          common["name"] = common.fetch("name").merge("description" => "name of the #{@kind}")
          list = collection.fetch("get").fetch("parameters")
          options = {
            list: list, delete_collection: list, read: list.select { |option| option["name"] == "resourceVersion" },
            create: collection.fetch("post").fetch("parameters"), replace: item.fetch("put").fetch("parameters"),
            patch: item.fetch("patch").fetch("parameters"), delete: item.fetch("delete").fetch("parameters")
          }
          [options, common]
        end

        def path_item(verbs, named: false, subresource: nil, all_namespaces: false)
          options = [@common.fetch("pretty")]
          options << @common.fetch("name") if named
          options << @common.fetch("namespace") if @namespaced && !all_namespaces
          options.concat(@options.fetch(:list)) if all_namespaces
          verbs.to_h do |verb|
            method, action, id_verb, codes = OPERATIONS.fetch(verb)
            model = response_model(verb, subresource)
            operation = {
              "operationId" => operation_id(verb, id_verb, subresource, all_namespaces),
              "description" => description(verb, id_verb, subresource), "tags" => [@tag],
              "responses" => responses(codes, model), "x-kubernetes-action" => action, GVK => @gvk
            }
            operation["parameters"] = @options.fetch(verb) unless all_namespaces
            body = request_body(verb, model)
            operation["requestBody"] = body if body
            [method, operation]
          end.merge("parameters" => options.sort_by { |option| option.fetch("name") })
        end

        def operation_id(verb, id_verb, subresource, all_namespaces)
          tail = if all_namespaces
                   "#{@kind}ForAllNamespaces"
                 else
                   scope = "Namespaced" if @namespaced
                   collection = "collection" if verb == :delete_collection
                   "#{collection}#{scope}#{@kind}#{subresource&.capitalize}"
                 end
          "#{id_verb}#{@id_scope}#{identifier(tail, upper: true)}"
        end

        def description(verb, id_verb, subresource)
          modifier = " #{subresource} of" if subresource
          case verb
          when :list then "list objects of kind #{@kind}"
          when :delete_collection then "delete collection of #{@kind}"
          when :create, :delete then "#{id_verb}#{article}#{@kind}"
          when :patch then "partially update#{modifier} the specified #{@kind}"
          else "#{id_verb}#{modifier} the specified #{@kind}"
          end
        end

        def article
          return " " if @kind.end_with?("s") && !@kind.end_with?("ss")

          @kind.match?(/\A[aeiou]/i) ? " an " : " a "
        end

        def response_model(verb, subresource)
          case verb
          when :list then @list_name
          when :delete, :delete_collection then "#{META}.Status"
          else subresource == "scale" ? SCALE : @definition_name
          end
        end

        def responses(codes, model)
          result = codes.to_h { |code| [code, {"description" => RESPONSE_DESCRIPTIONS.fetch(code), "content" => content(model, MEDIA)}] }
          result.merge("401" => {"description" => RESPONSE_DESCRIPTIONS.fetch("401")})
        end

        def request_body(verb, model)
          case verb
          when :create, :replace then {"required" => true, "content" => content(model, MEDIA)}
          when :patch then {"required" => true, "content" => content("#{META}.Patch", PATCH_MEDIA)}
          when :delete then {"content" => content(DELETE_OPTIONS, MEDIA)}
          end
        end

        def content(model, types)
          types.to_h { |type| [type, {"schema" => {"$ref" => "#/components/schemas/#{model}"}}] }
        end

        # Preserve capitalization within each name segment. Kubernetes only
        # uppercases the letter following punctuation or the first letter.
        def identifier(text, upper: false)
          result = +""
          text.each_char.with_index do |character, index|
            if character.match?(/[A-Za-z_]/) || (index.positive? && character.match?(/[0-9]/))
              result << (upper ? character.upcase : character)
              upper = false
            else
              upper = true
            end
          end
          result
        end
      end
    end
  end
end
