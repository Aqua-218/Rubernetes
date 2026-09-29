# frozen_string_literal: true

# Test/evidence-only adapter for Kubernetes REST strategy validation.  The
# pinned checkout used by M1 is intentionally sparse, so this adapter reads
# the complete pkg/ and staging/ trees from the pinned Git object into a
# temporary source tree before compiling the upstream strategy runner.

require "digest"
require "json"
require "open3"
require "tmpdir"

require_relative "m1_gate"

module M1KubernetesValidationOracle
  KUBERNETES_VERSION = "v1.36.2"
  SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
  KUBERNETES_MODULE = "k8s.io/kubernetes"

  class OracleError < StandardError; end

  # Executable collaborators for REST strategy constructors.  Every entry is
  # an upstream implementation shipped in the pinned checkout; the ledger
  # records which one was injected so the evidence stays reviewable.
  COLLABORATORS = [
    {
      "pattern" => /(?:^|\.)ObjectTyper\z/,
      "import" => "k8s.io/kubernetes/pkg/api/legacyscheme",
      "expression" => "%{alias}.Scheme",
      "implementation" => "legacyscheme.Scheme as the source-backed runtime.ObjectTyper",
      "source_path" => "pkg/api/legacyscheme/scheme.go"
    },
    {
      "pattern" => /(?:^|\.)Authorizer\z/,
      "import" => "k8s.io/apiserver/pkg/authorization/authorizerfactory",
      "expression" => "%{alias}.NewAlwaysAllowAuthorizer()",
      "implementation" => "authorizerfactory.NewAlwaysAllowAuthorizer: the AlwaysAllow authorization mode of kube-apiserver; the API differential requester is a system:masters identity for which every paramRef/paramKind access check is allowed",
      "source_path" => "staging/src/k8s.io/apiserver/pkg/authorization/authorizerfactory/builtin.go"
    },
    {
      "pattern" => /(?:^|\.)ResourceResolver\z/,
      "import" => "k8s.io/kubernetes/pkg/registry/admissionregistration/resolver",
      "expression" => "%{alias}.ResourceResolverFunc(builtinResourceResolver)",
      "implementation" => "resolver.ResourceResolverFunc over the legacyscheme registrations through meta.UnsafeGuessKindToResource, the same plural derivation NewDiscoveryResourceResolver observes for built-in kinds",
      "source_path" => "pkg/registry/admissionregistration/resolver/resolver.go",
      "helper" => "resource_resolver"
    },
    {
      "pattern" => /(?:^|\.)PolicyGetter\z/,
      "expression" => "fixturePolicyGetter{}",
      "implementation" => "runner PolicyGetter that reports NotFound; the binding fixtures carry no paramRef, so authorizeCreate/authorizeUpdate return before consulting it",
      "source_path" => "pkg/registry/admissionregistration/validatingadmissionpolicybinding/authz.go",
      "helper" => "policy_getter"
    },
    {
      "pattern" => /(?:^|\.)NamespaceInterface\z/,
      "import" => "k8s.io/client-go/kubernetes/fake",
      "expression" => "%{alias}.NewClientset().CoreV1().Namespaces()",
      "implementation" => "client-go fake Clientset NamespaceInterface with an empty store; the fixtures request no adminAccess, so AuthorizedForAdmin returns before any namespace lookup",
      "source_path" => "staging/src/k8s.io/client-go/kubernetes/fake/clientset_generated.go"
    }
  ].freeze

  # Resources whose validation runs inside a REST Create/Update handler
  # instead of a strategy.  `call` is the exact upstream validation entry the
  # handler invokes; fixtures are patches over the generated minimal object.
  HANDLER_ROOTS = {
    "io.k8s.api.authentication.v1.TokenRequest" => {
      "handler_source_path" => "pkg/registry/core/serviceaccount/storage/token.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/authentication/validation",
      "validation_source_path" => "pkg/apis/authentication/validation/validation.go",
      "call" => "%{validation}.ValidateTokenRequest(object.(*%{internal}.TokenRequest))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/authentication",
      "internal_type" => "TokenRequest",
      "version_import" => "k8s.io/kubernetes/pkg/apis/authentication/v1",
      "external_package" => "k8s.io/api/authentication/v1",
      "gvk" => {"group" => "authentication.k8s.io", "version" => "v1", "kind" => "TokenRequest"},
      "namespace_scoped" => true,
      "metadata_policy" => "name",
      "fixture" => {"create" => {"spec" => {"expirationSeconds" => 3600}}, "invalid" => {"spec" => {"expirationSeconds" => 1}}},
      "expectations" => {"create" => true, "invalid" => false, "missing" => true, "update" => true}
    },
    "io.k8s.api.authorization.v1.SubjectAccessReview" => {
      "handler_source_path" => "pkg/registry/authorization/subjectaccessreview/rest.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/authorization/validation",
      "validation_source_path" => "pkg/apis/authorization/validation/validation.go",
      "call" => "%{validation}.ValidateSubjectAccessReview(object.(*%{internal}.SubjectAccessReview))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/authorization",
      "internal_type" => "SubjectAccessReview",
      "version_import" => "k8s.io/kubernetes/pkg/apis/authorization/v1",
      "external_package" => "k8s.io/api/authorization/v1",
      "gvk" => {"group" => "authorization.k8s.io", "version" => "v1", "kind" => "SubjectAccessReview"},
      "namespace_scoped" => false,
      "metadata_policy" => "empty",
      "fixture" => {
        "update" => {"spec" => {"resourceAttributes" => {"verb" => "list"}}},
        "nested" => {
          "io.k8s.api.authorization.v1.NonResourceAttributes" => {
            "create" => {"spec" => {"resourceAttributes" => "__delete__", "user" => "m1-validation", "nonResourceAttributes" => {"path" => "/healthz", "verb" => "get"}}},
            "invalid" => {"spec" => {"resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods"}}},
            "update" => {"spec" => {"nonResourceAttributes" => {"verb" => "list"}}}
          },
          "io.k8s.api.authorization.v1.FieldSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.api.authorization.v1.LabelSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => {"requirements" => [{"key" => "app", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.apimachinery.pkg.apis.meta.v1.FieldSelectorRequirement" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}}
        },
        "create" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation",
                                "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => "__delete__"}}},
        "invalid" => {"spec" => {"user" => ""}}
      },
      "expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
    },
    "io.k8s.api.authorization.v1.SelfSubjectAccessReview" => {
      "handler_source_path" => "pkg/registry/authorization/selfsubjectaccessreview/rest.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/authorization/validation",
      "validation_source_path" => "pkg/apis/authorization/validation/validation.go",
      "call" => "%{validation}.ValidateSelfSubjectAccessReview(object.(*%{internal}.SelfSubjectAccessReview))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/authorization",
      "internal_type" => "SelfSubjectAccessReview",
      "version_import" => "k8s.io/kubernetes/pkg/apis/authorization/v1",
      "external_package" => "k8s.io/api/authorization/v1",
      "gvk" => {"group" => "authorization.k8s.io", "version" => "v1", "kind" => "SelfSubjectAccessReview"},
      "namespace_scoped" => false,
      "metadata_policy" => "empty",
      "fixture" => {
        "update" => {"spec" => {"resourceAttributes" => {"verb" => "list"}}},
        "nested" => {
          "io.k8s.api.authorization.v1.NonResourceAttributes" => {
            "create" => {"spec" => {"resourceAttributes" => "__delete__", "nonResourceAttributes" => {"path" => "/healthz", "verb" => "get"}}},
            "invalid" => {"spec" => {"resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods"}}},
            "update" => {"spec" => {"nonResourceAttributes" => {"verb" => "list"}}}
          },
          "io.k8s.api.authorization.v1.FieldSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.api.authorization.v1.LabelSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => {"requirements" => [{"key" => "app", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.apimachinery.pkg.apis.meta.v1.FieldSelectorRequirement" => {"spec" => {"nonResourceAttributes" => "__delete__", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}}
        },
        "create" => {"spec" => {"nonResourceAttributes" => "__delete__",
                                "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => "__delete__"}}},
        "invalid" => {"spec" => {"nonResourceAttributes" => {"path" => "/healthz", "verb" => "get"}}}
      },
      "expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
    },
    "io.k8s.api.authorization.v1.LocalSubjectAccessReview" => {
      "handler_source_path" => "pkg/registry/authorization/localsubjectaccessreview/rest.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/authorization/validation",
      "validation_source_path" => "pkg/apis/authorization/validation/validation.go",
      "call" => "%{validation}.ValidateLocalSubjectAccessReview(object.(*%{internal}.LocalSubjectAccessReview))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/authorization",
      "internal_type" => "LocalSubjectAccessReview",
      "version_import" => "k8s.io/kubernetes/pkg/apis/authorization/v1",
      "external_package" => "k8s.io/api/authorization/v1",
      "gvk" => {"group" => "authorization.k8s.io", "version" => "v1", "kind" => "LocalSubjectAccessReview"},
      "namespace_scoped" => true,
      "owner_rank" => 1,
      "metadata_policy" => "namespace_only",
      "fixture" => {
        "nested" => {
          "io.k8s.api.authorization.v1.FieldSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.api.authorization.v1.LabelSelectorAttributes" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => {"requirements" => [{"key" => "app", "operator" => "In", "values" => ["m1"]}]}}}},
          "io.k8s.apimachinery.pkg.apis.meta.v1.FieldSelectorRequirement" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation", "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "labelSelector" => "__delete__", "fieldSelector" => {"requirements" => [{"key" => "metadata.name", "operator" => "In", "values" => ["m1"]}]}}}}
        },
        "create" => {"spec" => {"nonResourceAttributes" => "__delete__", "user" => "m1-validation",
                                "resourceAttributes" => {"namespace" => "m1-validation", "verb" => "get", "resource" => "pods", "fieldSelector" => "__delete__", "labelSelector" => "__delete__"}}},
        "invalid" => {"spec" => {"resourceAttributes" => {"namespace" => "other-namespace"}}},
        "update" => {"spec" => {"resourceAttributes" => {"verb" => "list"}}}
      },
      "expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
    },
    "io.k8s.api.autoscaling.v1.Scale" => {
      "handler_source_path" => "pkg/registry/apps/deployment/storage/storage.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/autoscaling/validation",
      "validation_source_path" => "pkg/apis/autoscaling/validation/validation.go",
      "call" => "%{validation}.ValidateScale(object.(*%{internal}.Scale))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/autoscaling",
      "internal_type" => "Scale",
      "version_import" => "k8s.io/kubernetes/pkg/apis/autoscaling/v1",
      "external_package" => "k8s.io/api/autoscaling/v1",
      "gvk" => {"group" => "autoscaling", "version" => "v1", "kind" => "Scale"},
      "namespace_scoped" => true,
      "metadata_policy" => "name",
      "fixture" => {"create" => {"spec" => {"replicas" => 1}}, "invalid" => {"spec" => {"replicas" => -1}}},
      "expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
    },
    "io.k8s.api.core.v1.Binding" => {
      "handler_source_path" => "pkg/registry/core/pod/storage/storage.go",
      "validation_import" => "k8s.io/kubernetes/pkg/apis/core/validation",
      "validation_source_path" => "pkg/apis/core/validation/validation.go",
      "call" => "%{validation}.ValidatePodBinding(object.(*%{internal}.Binding))",
      "internal_package" => "k8s.io/kubernetes/pkg/apis/core",
      "internal_type" => "Binding",
      "version_import" => "k8s.io/kubernetes/pkg/apis/core/v1",
      "external_package" => "k8s.io/api/core/v1",
      "gvk" => {"group" => "", "version" => "v1", "kind" => "Binding"},
      "namespace_scoped" => true,
      "metadata_policy" => "name",
      "fixture" => {"create" => {"target" => {"kind" => "Node", "name" => "m1-node"}}, "invalid" => {"target" => {"kind" => "Deployment", "name" => "m1-node"}}},
      "expectations" => {"create" => true, "invalid" => false, "missing" => false, "update" => true}
    },
    "io.k8s.apimachinery.pkg.apis.meta.v1.DeleteOptions" => {
      "handler_source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/handlers/delete.go",
      "validation_import" => "k8s.io/apimachinery/pkg/apis/meta/v1/validation",
      "validation_source_path" => "staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/validation/validation.go",
      "call" => "%{validation}.ValidateDeleteOptions(object.(*%{versioned}.DeleteOptions))",
      "internal_package" => nil,
      "internal_type" => "DeleteOptions",
      "version_import" => "k8s.io/apimachinery/pkg/apis/meta/v1",
      "external_package" => "k8s.io/apimachinery/pkg/apis/meta/v1",
      "gvk" => {"group" => "", "version" => "v1", "kind" => "DeleteOptions"},
      "namespace_scoped" => false,
      "metadata_policy" => "none",
      "fixture" => {"create" => {"propagationPolicy" => "Background"}, "invalid" => {"propagationPolicy" => "Bogus"}},
      "expectations" => {"create" => true, "invalid" => false, "missing" => true, "update" => true}
    }
  }.freeze

  # Virtual resources whose REST handlers validate by direct checks and whose
  # observable behavior is captured against the isolated kube-apiserver in the
  # M1 API differential (operation ids below).
  REST_ENDPOINT_ROOTS = {
    "io.k8s.api.authentication.v1.TokenReview" => {
      "handler_source_path" => "pkg/registry/authentication/tokenreview/storage.go",
      "api_operations" => %w[tokenreview-create tokenreview-missing-token],
      "gvk" => {"group" => "authentication.k8s.io", "version" => "v1", "kind" => "TokenReview"}
    },
    "io.k8s.api.authentication.v1.SelfSubjectReview" => {
      "handler_source_path" => "pkg/registry/authentication/selfsubjectreview/rest.go",
      "api_operations" => %w[selfsubjectreview-create],
      "gvk" => {"group" => "authentication.k8s.io", "version" => "v1", "kind" => "SelfSubjectReview"}
    },
    "io.k8s.api.authorization.v1.SelfSubjectRulesReview" => {
      "handler_source_path" => "pkg/registry/authorization/selfsubjectrulesreview/rest.go",
      "api_operations" => %w[selfsubjectrulesreview-create selfsubjectrulesreview-missing-namespace],
      "gvk" => {"group" => "authorization.k8s.io", "version" => "v1", "kind" => "SelfSubjectRulesReview"}
    },
    "io.k8s.api.policy.v1.Eviction" => {
      "handler_source_path" => "pkg/registry/core/pod/storage/eviction.go",
      "api_operations" => %w[eviction-create eviction-invalid-delete-options],
      "gvk" => {"group" => "policy", "version" => "v1", "kind" => "Eviction"}
    },
    "io.k8s.api.core.v1.ComponentStatus" => {
      "handler_source_path" => "pkg/registry/core/componentstatus/rest.go",
      "api_operations" => %w[componentstatus-list componentstatus-get],
      "gvk" => {"group" => "", "version" => "v1", "kind" => "ComponentStatus"}
    }
  }.freeze

  # Server-generated protocol types: never submitted for create/update, they
  # are validated as kube-apiserver responses in the API differential.
  RESPONSE_ROOTS = {
    "io.k8s.apimachinery.pkg.apis.meta.v1.APIVersions" => {"api_operations" => %w[/api], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/discovery/legacy.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.APIGroupList" => {"api_operations" => %w[/apis], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/discovery/root.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.APIGroup" => {"api_operations" => %w[/apis/apps], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/discovery/group.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.APIResourceList" => {"api_operations" => %w[/api/v1 /apis/apps/v1], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/discovery/version.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.Status" => {"api_operations" => %w[duplicate-create-status validation-status not-found-status delete], "source_path" => "staging/src/k8s.io/apimachinery/pkg/api/errors/errors.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta" => {"api_operations" => %w[list], "source_path" => "staging/src/k8s.io/apiserver/pkg/registry/generic/registry/store.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.Patch" => {"api_operations" => %w[merge-patch apply-create apply-force], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go"},
    "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent" => {"api_operations" => %w[watch initial-watch], "source_path" => "staging/src/k8s.io/apiserver/pkg/endpoints/handlers/watch.go"}
  }.freeze

  VALIDATION_MODES = %w[strategy constructor handler list rest_endpoint response].freeze

  # REST strategy roots whose generated minimal object is not a valid upstream
  # object.  Each patch is the smallest upstream-cited change that lets the
  # pinned strategy accept the create fixture; "nested" patches keep an
  # embedded descriptor valid where the owner-level patch would otherwise
  # conflict with it (patches are keyed by full schema id or by the schema's
  # last name segment so every served version shares one entry).
  MATCH_RESOURCES_FIXTURE = {
    "matchPolicy" => "Equivalent", "namespaceSelector" => {}, "objectSelector" => {},
    "resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}]
  }.freeze
  ADMISSION_POLICY_COMMON_FIXTURE = {
    "failurePolicy" => "Fail",
    "paramKind" => {"apiVersion" => "v1", "kind" => "ConfigMap"},
    "matchConstraints" => MATCH_RESOURCES_FIXTURE,
    "matchConditions" => [{"name" => "m1-condition", "expression" => "true"}],
    "variables" => [{"name" => "m1Variable", "expression" => "true"}]
  }.freeze
  # pkg/apis/certificates/validation validateStubPKCS10Request: a P-256
  # ECDSA PKCS#10 request with a verifiable self-signature.
  POD_CERTIFICATE_REQUEST_PKCS10 = "MIHRMHoCAQAwGDEWMBQGA1UEAwwNbTEtdmFsaWRhdGlvbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIdtIXc9HCwvsOAJqA6PUM5lhZHiZhmlfk9Mt100SDa0ViUkQJn1vPW+QaxUuAi5+dHE3WjD2hpMFR/HLVSo+oqgADAKBggqhkjOPQQDAgNHADBEAiBn50/kpQVXLGKi8QaSmS4/fg3D6rNmqqZ42OuUyz4BMQIgAjkGdOkNIwk2s2vpB7dfP3vW0BzCws4oO8KB6W3Oat0="
  STRATEGY_FIXTURES = {
    ["admissionregistration.k8s.io", "MutatingAdmissionPolicy"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateMutatingAdmissionPolicySpec",
      "fixture" => {
        "create" => {"spec" => ADMISSION_POLICY_COMMON_FIXTURE.merge(
          "mutations" => [{"patchType" => "JSONPatch", "applyConfiguration" => "__delete__",
                           "jsonPatch" => {"expression" => "[JSONPatch{op: \"add\", path: \"/metadata/labels/m1\", value: \"m1\"}]"}}],
          "reinvocationPolicy" => "Never"
        )},
        "nested" => {
          "ApplyConfiguration" => {"spec" => {"mutations" => [{"patchType" => "ApplyConfiguration", "jsonPatch" => "__delete__",
                                                               "applyConfiguration" => {"expression" => "Object{metadata: Object.metadata{labels: {\"m1\": \"m1\"}}}"}}]}},
          "NamedRuleWithOperations" => {"spec" => {"matchConstraints" => {"excludeResourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}]}}},
          "ManagedFieldsEntry" => {"metadata" => {"managedFields" => [{"manager" => "m1", "operation" => "Update", "apiVersion" => "admissionregistration.k8s.io/v1", "fieldsType" => "FieldsV1", "fieldsV1" => {"f:spec" => {}}}]}},
          "FieldsV1" => {"metadata" => {"managedFields" => [{"manager" => "m1", "operation" => "Update", "apiVersion" => "admissionregistration.k8s.io/v1", "fieldsType" => "FieldsV1", "fieldsV1" => {"f:spec" => {}}}]}}
        }
      }
    },
    ["admissionregistration.k8s.io", "MutatingAdmissionPolicyBinding"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateMutatingAdmissionPolicyBindingSpec",
      "fixture" => {
        "create" => {"spec" => {"policyName" => "m1-policy",
                                "paramRef" => {"name" => "m1-param", "selector" => "__delete__", "parameterNotFoundAction" => "Deny"},
                                "matchResources" => MATCH_RESOURCES_FIXTURE}},
        "nested" => {"NamedRuleWithOperations" => {"spec" => {"matchResources" => {"excludeResourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}]}}}}
      }
    },
    ["admissionregistration.k8s.io", "ValidatingAdmissionPolicy"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateValidatingAdmissionPolicySpec",
      "fixture" => {
        "create" => {"spec" => ADMISSION_POLICY_COMMON_FIXTURE.merge(
          "validations" => [{"expression" => "true", "message" => "m1 validation"}],
          "auditAnnotations" => [{"key" => "m1-audit", "valueExpression" => "'m1'"}]
        )},
        "nested" => {"NamedRuleWithOperations" => {"spec" => {"matchConstraints" => {"excludeResourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}]}}}}
      }
    },
    ["apiextensions.k8s.io", "CustomResourceDefinition"] => {
      "source" => "staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation/validation.go ValidateCustomResourceDefinition",
      "fixture" => {
        "create" => {
          "metadata" => {"name" => "widgets.m1.example.com"},
          "spec" => {
            "group" => "m1.example.com", "scope" => "Namespaced", "preserveUnknownFields" => false,
            "names" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "listKind" => "WidgetList", "shortNames" => ["wd"], "categories" => ["m1"]},
            "versions" => [{
              "name" => "v1", "served" => true, "storage" => true,
              "schema" => {"openAPIV3Schema" => {
                "type" => "object",
                "properties" => {
                  "spec" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer"}}},
                  "status" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer"}}}
                }
              }},
              "subresources" => {"status" => {}, "scale" => {"specReplicasPath" => ".spec.replicas", "statusReplicasPath" => ".status.replicas"}},
              "additionalPrinterColumns" => [{"name" => "Replicas", "type" => "integer", "jsonPath" => ".spec.replicas"}],
              "selectableFields" => [{"jsonPath" => ".spec.replicas"}]
            }],
            "conversion" => {"strategy" => "None", "webhook" => "__delete__"}
          },
          # The update path validates the retained status (acceptedNames,
          # storedVersions) of the stored object.
          "status" => {"acceptedNames" => {"plural" => "widgets", "singular" => "widget", "kind" => "Widget", "listKind" => "WidgetList", "shortNames" => ["wd"], "categories" => ["m1"]},
                       "storedVersions" => ["v1"], "conditions" => "__delete__"}
        },
        "nested" => {
          "WebhookConversion" => {"spec" => {"conversion" => {"strategy" => "Webhook", "webhook" => {"conversionReviewVersions" => ["v1"], "clientConfig" => {"url" => "__delete__", "service" => {"name" => "m1", "namespace" => "m1", "path" => "/convert", "port" => 443}}}}}},
          "WebhookClientConfig" => {"spec" => {"conversion" => {"strategy" => "Webhook", "webhook" => {"conversionReviewVersions" => ["v1"], "clientConfig" => {"url" => "__delete__", "service" => {"name" => "m1", "namespace" => "m1", "path" => "/convert", "port" => 443}}}}}},
          "ServiceReference" => {"spec" => {"conversion" => {"strategy" => "Webhook", "webhook" => {"conversionReviewVersions" => ["v1"], "clientConfig" => {"url" => "__delete__", "service" => {"name" => "m1", "namespace" => "m1", "path" => "/convert", "port" => 443}}}}}},
          # A schema at the root of a CRD must be an object; array items live
          # under a property.  The descriptor's own root slot is removed.
          "JSONSchemaPropsOrArray" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"type" => "object", "items" => "__delete__", "properties" => {"list" => {"type" => "array", "items" => {"type" => "string"}}}}}}]}},
          # The wire form of JSONSchemaPropsOrBool is either a bool or a schema;
          # additionalItems is not supported by CRDs, so the descriptor is
          # exercised through additionalProperties of a map property.
          "JSONSchemaPropsOrBool" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"type" => "object", "additionalItems" => "__delete__", "additionalProperties" => "__delete__", "properties" => {"labels" => {"type" => "object", "additionalProperties" => {"type" => "string"}}}}}}]}},
          "JSONSchemaPropsOrStringArray" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"type" => "object", "dependencies" => "__delete__", "properties" => {"spec" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer"}}}}}}}]}},
          "ValidationRule" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"x-kubernetes-validations" => [{"rule" => "true", "message" => "m1"}]}}}]}},
          "ExternalDocumentation" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"externalDocs" => {"url" => "https://m1.example.com/docs", "description" => "m1"}}}}]}},
          # A root-level default is not allowed with the status subresource;
          # the JSON carrier is exercised as an example and a nested default.
          "JSON" => {"spec" => {"versions" => [{"schema" => {"openAPIV3Schema" => {"type" => "object", "default" => "__delete__", "example" => {"spec" => {"replicas" => 1}}, "properties" => {"spec" => {"type" => "object", "properties" => {"replicas" => {"type" => "integer", "default" => 1}}}}}}}]}}
        }
      }
    },
    ["certificates.k8s.io", "PodCertificateRequest"] => {
      "source" => "pkg/apis/certificates/validation/validation.go ValidatePodCertificateRequestCreate",
      "fixture" => {
        "create" => {"spec" => {
          "signerName" => "m1.example.com/signer", "podName" => "m1-pod", "podUID" => "m1-pod-uid",
          "serviceAccountName" => "m1-sa", "serviceAccountUID" => "m1-sa-uid", "nodeName" => "m1-node", "nodeUID" => "m1-node-uid",
          "maxExpirationSeconds" => 86_400, "stubPKCS10Request" => POD_CERTIFICATE_REQUEST_PKCS10,
          "pkixPublicKey" => "__delete__", "proofOfPossession" => "__delete__"
        }}
      }
    },
    ["resource.k8s.io", "DeviceTaintRule"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateDeviceTaintRuleSpec",
      "fixture" => {
        "create" => {"spec" => {"taint" => {"key" => "m1.example.com/taint", "value" => "m1", "effect" => "NoSchedule"},
                                "deviceSelector" => {"driver" => "m1.example.com", "pool" => "m1-pool", "device" => "m1-device"}}}
      }
    },
    ["internal.apiserver.k8s.io", "StorageVersion"] => {
      "source" => "pkg/apis/apiserverinternal/validation/validation.go ValidateStorageVersionName",
      "fixture" => {
        "create" => {"metadata" => {"name" => "apps.deployments"}},
        "nested" => {
          "ServerStorageVersion" => {"status" => {"storageVersions" => [{"apiServerID" => "m1-apiserver", "encodingVersion" => "apps/v1", "decodableVersions" => ["apps/v1"], "servedVersions" => ["apps/v1"]}], "commonEncodingVersion" => "apps/v1"}}
        }
      }
    },
    ["networking.k8s.io", "IPAddress"] => {
      "source" => "pkg/apis/networking/validation/validation.go ValidateIPAddress",
      "fixture" => {
        "create" => {"metadata" => {"name" => "10.0.0.1"},
                     "spec" => {"parentRef" => {"group" => "", "resource" => "services", "namespace" => "m1-validation", "name" => "m1"}}}
      }
    },
    ["apiregistration.k8s.io", "APIService"] => {
      "source" => "staging/src/k8s.io/kube-aggregator/pkg/apis/apiregistration/validation/validation.go ValidateAPIService",
      "fixture" => {
        "create" => {"metadata" => {"name" => "v1.m1.example.com"},
                     "spec" => {"group" => "m1.example.com", "version" => "v1", "groupPriorityMinimum" => 100, "versionPriority" => 10,
                                "service" => {"name" => "m1", "namespace" => "m1", "port" => 443}, "caBundle" => "__delete__", "insecureSkipTLSVerify" => true}}
      }
    },
    ["scheduling.k8s.io", "PodGroup"] => {
      "source" => "staging/src/k8s.io/api/scheduling/v1alpha2/types.go declarative validation (schedulingPolicy union)",
      "fixture" => {
        "create" => {"spec" => {"schedulingPolicy" => {"basic" => {}, "gang" => "__delete__"}}},
        "nested" => {
          "GangSchedulingPolicy" => {"spec" => {"schedulingPolicy" => {"basic" => "__delete__", "gang" => {"minCount" => 1}}}},
          "PodGroupTemplateReference" => {"spec" => {"podGroupTemplateRef" => {"workload" => {"workloadName" => "m1-workload", "podGroupTemplateName" => "m1-template"}}}},
          "WorkloadPodGroupTemplateReference" => {"spec" => {"podGroupTemplateRef" => {"workload" => {"workloadName" => "m1-workload", "podGroupTemplateName" => "m1-template"}}}},
          "PodGroupResourceClaim" => {"spec" => {"resourceClaims" => [{"name" => "m1-claim", "resourceClaimName" => "m1-claim", "resourceClaimTemplateName" => "__delete__"}]}},
        }
      }
    },
    ["scheduling.k8s.io", "Workload"] => {
      "source" => "staging/src/k8s.io/api/scheduling/v1alpha2/types.go declarative validation (podGroupTemplates required)",
      "fixture" => {
        "create" => {"spec" => {"podGroupTemplates" => [{"name" => "m1-template", "schedulingPolicy" => {"basic" => {}, "gang" => "__delete__"}}]}},
        "nested" => {
          "GangSchedulingPolicy" => {"spec" => {"podGroupTemplates" => [{"schedulingPolicy" => {"basic" => "__delete__", "gang" => {"minCount" => 1}}}]}},
          "TypedLocalObjectReference" => {"spec" => {"controllerRef" => {"apiGroup" => "apps", "kind" => "Deployment", "name" => "m1"}}},
          "PodGroupResourceClaim" => {"spec" => {"podGroupTemplates" => [{"resourceClaims" => [{"name" => "m1-claim", "resourceClaimName" => "m1-claim", "resourceClaimTemplateName" => "__delete__"}]}]}}
        }
      }
    },
    ["", "Pod"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidatePodSpec (valid container, volume, env, probe and scheduling descriptors)",
      "fixture" => {
        "create" => {"spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}},
        "nested" => {
          "AppArmorProfile" => {"spec" => {"securityContext" => {"appArmorProfile" => {"type" => "RuntimeDefault", "localhostProfile" => "__delete__"}}, "containers" => [{"securityContext" => {"appArmorProfile" => {"type" => "RuntimeDefault", "localhostProfile" => "__delete__"}}}]}},
          "SeccompProfile" => {"spec" => {"securityContext" => {"seccompProfile" => {"type" => "RuntimeDefault", "localhostProfile" => "__delete__"}}, "containers" => [{"securityContext" => {"seccompProfile" => {"type" => "RuntimeDefault", "localhostProfile" => "__delete__"}}}]}},
          "AzureFileVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "azureFile" => {"secretName" => "m1", "shareName" => "m1"}}]}},
          "CSIVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "csi" => {"driver" => "m1.example.com"}}]}},
          "CephFSVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "cephfs" => {"monitors" => ["10.0.0.1:6789"]}}]}},
          "CinderVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "cinder" => {"volumeID" => "m1"}}]}},
          "ClusterTrustBundleProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"clusterTrustBundle" => {"name" => "m1", "signerName" => "__delete__", "labelSelector" => "__delete__", "path" => "ca.pem"}}]}}]}},
          "ConfigMapEnvSource" => {"spec" => {"containers" => [{"envFrom" => [{"configMapRef" => {"name" => "m1"}, "secretRef" => "__delete__"}]}]}},
          "SecretEnvSource" => {"spec" => {"containers" => [{"envFrom" => [{"secretRef" => {"name" => "m1"}, "configMapRef" => "__delete__"}]}]}},
          "EnvFromSource" => {"spec" => {"containers" => [{"envFrom" => [{"configMapRef" => {"name" => "m1"}, "secretRef" => "__delete__"}]}]}},
          "ConfigMapKeySelector" => {"spec" => {"containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"configMapKeyRef" => {"name" => "m1", "key" => "k"}, "fieldRef" => "__delete__", "resourceFieldRef" => "__delete__", "secretKeyRef" => "__delete__", "fileKeyRef" => "__delete__"}}]}]}},
          "SecretKeySelector" => {"spec" => {"containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"secretKeyRef" => {"name" => "m1", "key" => "k"}, "fieldRef" => "__delete__", "resourceFieldRef" => "__delete__", "configMapKeyRef" => "__delete__", "fileKeyRef" => "__delete__"}}]}]}},
          "ObjectFieldSelector" => {"spec" => {"containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.name"}, "resourceFieldRef" => "__delete__", "configMapKeyRef" => "__delete__", "secretKeyRef" => "__delete__", "fileKeyRef" => "__delete__"}}]}]}},
          "EnvVarSource" => {"spec" => {"containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.name"}, "resourceFieldRef" => "__delete__", "configMapKeyRef" => "__delete__", "secretKeyRef" => "__delete__", "fileKeyRef" => "__delete__"}}]}]}},
          "ResourceFieldSelector" => {"spec" => {"containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"resourceFieldRef" => {"resource" => "limits.cpu", "containerName" => "__delete__", "divisor" => "__delete__"}, "fieldRef" => "__delete__", "configMapKeyRef" => "__delete__", "secretKeyRef" => "__delete__", "fileKeyRef" => "__delete__"}}]}]}},
          "FileKeySelector" => {"spec" => {"volumes" => [{"name" => "m1-volume", "emptyDir" => {}}], "containers" => [{"env" => [{"name" => "M1", "value" => "__delete__", "valueFrom" => {"fileKeyRef" => {"volumeName" => "m1-volume", "path" => "m1.env", "key" => "K"}, "fieldRef" => "__delete__", "resourceFieldRef" => "__delete__", "configMapKeyRef" => "__delete__", "secretKeyRef" => "__delete__"}}]}]}},
          "ConfigMapProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"configMap" => {"name" => "m1"}}]}}]}},
          "SecretProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"secret" => {"name" => "m1"}}]}}]}},
          "ProjectedVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"configMap" => {"name" => "m1"}}]}}]}},
          "VolumeProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"configMap" => {"name" => "m1"}, "secret" => "__delete__", "downwardAPI" => "__delete__", "serviceAccountToken" => "__delete__", "clusterTrustBundle" => "__delete__", "podCertificate" => "__delete__"}]}}]}},
          "DownwardAPIProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"downwardAPI" => {"items" => [{"path" => "m1", "fieldRef" => {"fieldPath" => "metadata.name"}}]}}]}}]}},
          "ServiceAccountTokenProjection" => {"spec" => {"serviceAccountName" => "m1", "volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"serviceAccountToken" => {"path" => "token", "audience" => "__delete__", "expirationSeconds" => "__delete__"}}]}}]}},
          "PodCertificateProjection" => {"spec" => {"volumes" => [{"name" => "m1-volume", "projected" => {"sources" => [{"podCertificate" => {"signerName" => "m1.example.com/signer", "keyType" => "ED25519", "credentialBundlePath" => "creds", "keyPath" => "__delete__", "certificateChainPath" => "__delete__", "maxExpirationSeconds" => "__delete__"}}]}}]}},
          "ConfigMapVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "configMap" => {"name" => "m1"}}]}},
          "KeyToPath" => {"spec" => {"volumes" => [{"name" => "m1-volume", "configMap" => {"name" => "m1", "items" => [{"key" => "k", "path" => "k"}]}}]}},
          "SecretVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "secret" => {"secretName" => "m1"}}]}},
          "DownwardAPIVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "downwardAPI" => {"items" => [{"path" => "m1", "fieldRef" => {"fieldPath" => "metadata.name"}}]}}]}},
          "DownwardAPIVolumeFile" => {"spec" => {"volumes" => [{"name" => "m1-volume", "downwardAPI" => {"items" => [{"path" => "m1", "fieldRef" => {"fieldPath" => "metadata.name"}, "resourceFieldRef" => "__delete__"}]}}]}},
          "EmptyDirVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "emptyDir" => {}}]}},
          "EphemeralVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "ephemeral" => {"volumeClaimTemplate" => {"spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}}}}]}},
          "PersistentVolumeClaimTemplate" => {"spec" => {"volumes" => [{"name" => "m1-volume", "ephemeral" => {"volumeClaimTemplate" => {"spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}}}}]}},
          "FlexVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "flexVolume" => {"driver" => "m1.example.com/driver"}}]}},
          "GitRepoVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "gitRepo" => {"repository" => "https://m1.example.com/repo.git"}}]}},
          "GlusterfsVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "glusterfs" => {"endpoints" => "m1", "path" => "m1"}}]}},
          "ISCSIVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "iscsi" => {"targetPortal" => "10.0.0.1:3260", "iqn" => "iqn.2026-01.com.example:m1", "lun" => 0}}]}},
          "ImageVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "image" => {"reference" => "m1.example.com/data:1"}}]}},
          "PersistentVolumeClaimVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "persistentVolumeClaim" => {"claimName" => "m1"}}]}},
          "RBDVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "rbd" => {"monitors" => ["10.0.0.1:6789"], "image" => "m1"}}]}},
          "ScaleIOVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "scaleIO" => {"gateway" => "https://m1.example.com", "system" => "m1", "volumeName" => "m1", "secretRef" => {"name" => "m1"}}}]}},
          "StorageOSVolumeSource" => {"spec" => {"volumes" => [{"name" => "m1-volume", "storageos" => {"volumeName" => "m1"}}]}},
          "ContainerResizePolicy" => {"spec" => {"containers" => [{"resizePolicy" => [{"resourceName" => "cpu", "restartPolicy" => "NotRequired"}]}]}},
          "ContainerRestartRule" => {"spec" => {"containers" => [{"restartPolicy" => "Never", "restartPolicyRules" => [{"action" => "Restart", "exitCodes" => {"operator" => "In", "values" => [1]}}]}]}},
          "ContainerRestartRuleOnExitCodes" => {"spec" => {"containers" => [{"restartPolicy" => "Never", "restartPolicyRules" => [{"action" => "Restart", "exitCodes" => {"operator" => "In", "values" => [1]}}]}]}},
          "ExecAction" => {"spec" => {"containers" => [{"livenessProbe" => {"httpGet" => "__delete__", "tcpSocket" => "__delete__", "grpc" => "__delete__", "exec" => {"command" => ["/bin/true"]}}}]}},
          "Probe" => {"spec" => {"containers" => [{"livenessProbe" => {"httpGet" => "__delete__", "tcpSocket" => "__delete__", "grpc" => "__delete__", "exec" => {"command" => ["/bin/true"]}}}]}},
          "HTTPGetAction" => {"spec" => {"containers" => [{"livenessProbe" => {"exec" => "__delete__", "tcpSocket" => "__delete__", "grpc" => "__delete__", "httpGet" => {"port" => 80, "path" => "/healthz", "scheme" => "__delete__"}}}]}},
          "HTTPHeader" => {"spec" => {"containers" => [{"livenessProbe" => {"exec" => "__delete__", "tcpSocket" => "__delete__", "grpc" => "__delete__", "httpGet" => {"port" => 80, "path" => "/healthz", "scheme" => "__delete__", "httpHeaders" => [{"name" => "X-M1", "value" => "1"}]}}}]}},
          "TCPSocketAction" => {"spec" => {"containers" => [{"livenessProbe" => {"exec" => "__delete__", "httpGet" => "__delete__", "grpc" => "__delete__", "tcpSocket" => {"port" => 80, "host" => "__delete__"}}}]}},
          "LifecycleHandler" => {"spec" => {"containers" => [{"lifecycle" => {"postStart" => {"exec" => {"command" => ["/bin/true"]}, "httpGet" => "__delete__", "tcpSocket" => "__delete__", "sleep" => "__delete__"}, "preStop" => "__delete__"}}]}},
          "HostAlias" => {"spec" => {"hostAliases" => [{"ip" => "10.0.0.1", "hostnames" => ["m1.example.com"]}]}},
          "PodDNSConfigOption" => {"spec" => {"dnsConfig" => {"options" => [{"name" => "ndots", "value" => "2"}]}}},
          "PodOS" => {"spec" => {"os" => {"name" => "linux"}}},
          "PodResourceClaim" => {"spec" => {"resourceClaims" => [{"name" => "m1-claim", "resourceClaimName" => "m1", "resourceClaimTemplateName" => "__delete__"}]}},
          "PodSchedulingGroup" => {"spec" => {"schedulingGroup" => {"podGroupName" => "m1"}}},
          "ResourceClaim" => {"spec" => {"resources" => "__delete__", "resourceClaims" => [{"name" => "m1-claim", "resourceClaimName" => "m1"}], "containers" => [{"resources" => {"claims" => [{"name" => "m1-claim"}]}}]}},
          "Toleration" => {"spec" => {"tolerations" => [{"key" => "m1", "operator" => "Exists", "value" => "__delete__"}]}},
          "TopologySpreadConstraint" => {"spec" => {"topologySpreadConstraints" => [{"maxSkew" => 1, "topologyKey" => "topology.kubernetes.io/zone", "whenUnsatisfiable" => "DoNotSchedule"}]}},
          "VolumeMount" => {"spec" => {"volumes" => [{"name" => "m1-volume", "emptyDir" => {}}], "containers" => [{"volumeMounts" => [{"name" => "m1-volume", "mountPath" => "/m1"}]}]}},
          "VolumeDevice" => {"spec" => {"volumes" => [{"name" => "m1-volume", "persistentVolumeClaim" => {"claimName" => "m1"}}], "containers" => [{"volumeDevices" => [{"name" => "m1-volume", "devicePath" => "/dev/m1"}]}]}},
          "EphemeralContainer" => {
            "create" => {"spec" => {"ephemeralContainers" => [{"name" => "m1-debug", "image" => "m1.example.com/pause:1"}]}},
            # Ephemeral containers are only reachable through the subresource on
            # create; an unchanged list passes the update validation.
            "expectations" => {"create" => false, "invalid" => false, "update" => true, "missing" => false}
          }
        }
      }
    },
    ["apps", "Deployment"] => {
      "source" => "pkg/apis/apps/validation/validation.go ValidateDeploymentSpec (selector must match template labels)",
      "fixture" => {"create" => {"spec" => {"selector" => {"matchLabels" => {"app" => "m1"}},
                                            "template" => {"metadata" => {"labels" => {"app" => "m1"}}, "spec" => {"containers" => [{"image" => "m1.example.com/pause:1"}]}}}}}
    },
    ["batch", "Job"] => {
      "source" => "pkg/apis/batch/validation/validation.go validateJobSpec (pod template must be valid)",
      # manualSelector keeps the strategy from generating the controller-uid
      # selector, which needs the server-assigned UID that FillObjectMetaSystemFields
      # supplies only inside kube-apiserver's BeforeCreate.
      "fixture" => {
        "create" => {"spec" => {"manualSelector" => true, "selector" => {"matchLabels" => {"job" => "m1"}},
                                "template" => {"metadata" => {"labels" => {"job" => "m1"}},
                                               "spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}}},
        "nested" => {
          "PodFailurePolicy" => {"spec" => {"podFailurePolicy" => {"rules" => [{"action" => "FailJob", "onPodConditions" => "__delete__", "onExitCodes" => {"operator" => "In", "values" => [1]}}]}}},
          "PodFailurePolicyRule" => {"spec" => {"podFailurePolicy" => {"rules" => [{"action" => "FailJob", "onPodConditions" => "__delete__", "onExitCodes" => {"operator" => "In", "values" => [1]}}]}}},
          "PodFailurePolicyOnExitCodesRequirement" => {"spec" => {"podFailurePolicy" => {"rules" => [{"action" => "FailJob", "onPodConditions" => "__delete__", "onExitCodes" => {"operator" => "In", "values" => [1]}}]}}},
          "PodFailurePolicyOnPodConditionsPattern" => {"spec" => {"podFailurePolicy" => {"rules" => [{"action" => "FailJob", "onExitCodes" => "__delete__", "onPodConditions" => [{"type" => "DisruptionTarget", "status" => "True"}]}]}}},
          "SuccessPolicy" => {"spec" => {"completionMode" => "Indexed", "completions" => 2, "parallelism" => 1, "successPolicy" => {"rules" => [{"succeededIndexes" => "0", "succeededCount" => "__delete__"}]}}},
          "SuccessPolicyRule" => {"spec" => {"completionMode" => "Indexed", "completions" => 2, "parallelism" => 1, "successPolicy" => {"rules" => [{"succeededIndexes" => "0", "succeededCount" => "__delete__"}]}}}
        }
      }
    },
    ["", "LimitRange"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidateLimitRange (standard limit type)",
      # ValidateLimitRange runs before ObjectMeta validation and accepts the
      # zero-value name, so the negative observation is an invalid limit type.
      "fixture" => {"create" => {"spec" => {"limits" => [{"type" => "Container"}]}},
                    "invalid" => {"spec" => {"limits" => [{"type" => "m1-invalid"}]}}}
    },
    ["admissionregistration.k8s.io", "ValidatingAdmissionPolicyBinding"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateValidationActions",
      "fixture" => {"create" => {"spec" => {"validationActions" => ["Deny"]}},
                    "nested" => {"NamedRuleWithOperations" => {"spec" => {"matchResources" => {"excludeResourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}]}}}}}
    },
    ["policy", "PodDisruptionBudget"] => {
      "source" => "pkg/apis/policy/validation/validation.go ValidatePodDisruptionBudgetSpec (ObjectMeta is not validated by the strategy)",
      "fixture" => {"invalid" => {"spec" => {"minAvailable" => 1, "maxUnavailable" => 1}}},
      "expectations" => {"create" => true, "invalid" => false, "update" => true, "missing" => true}
    },

    ["apps", "DaemonSet"] => {
      "source" => "pkg/apis/apps/validation/validation.go ValidateDaemonSetSpec",
      "fixture" => {"create" => {"spec" => {"selector" => {"matchLabels" => {"app" => "m1"}}, "template" => {"metadata" => {"labels" => {"app" => "m1"}}, "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}}}}
    },
    ["apps", "ReplicaSet"] => {
      "source" => "pkg/apis/apps/validation/validation.go ValidateReplicaSetSpec",
      "fixture" => {"create" => {"spec" => {"selector" => {"matchLabels" => {"app" => "m1"}}, "template" => {"metadata" => {"labels" => {"app" => "m1"}}, "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}}}}
    },
    ["apps", "StatefulSet"] => {
      "source" => "pkg/apis/apps/validation/validation.go ValidateStatefulSetSpec",
      "fixture" => {"create" => {"spec" => {"selector" => {"matchLabels" => {"app" => "m1"}}, "template" => {"metadata" => {"labels" => {"app" => "m1"}}, "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}}}}
    },
    ["autoscaling", "HorizontalPodAutoscaler"] => {
      "source" => "pkg/apis/autoscaling/validation/validation.go validateMetricSpec",
      "fixture" => {
        "create" => {"spec" => {"scaleTargetRef" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "m1"}, "maxReplicas" => 2}},
        "nested" => {
          "MetricSpec" => {"spec" => {"metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 50}}, "containerResource" => "__delete__", "external" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "ResourceMetricSource" => {"spec" => {"metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 50}}, "containerResource" => "__delete__", "external" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "MetricTarget" => {"spec" => {"metrics" => [{"type" => "Resource", "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 50}}, "containerResource" => "__delete__", "external" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "ContainerResourceMetricSource" => {"spec" => {"metrics" => [{"type" => "ContainerResource", "containerResource" => {"name" => "cpu", "container" => "m1", "target" => {"type" => "Utilization", "averageUtilization" => 50}}, "resource" => "__delete__", "external" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "ExternalMetricSource" => {"spec" => {"metrics" => [{"type" => "External", "external" => {"metric" => {"name" => "m1-metric"}, "target" => {"type" => "Value", "value" => "1"}}, "resource" => "__delete__", "containerResource" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "MetricIdentifier" => {"spec" => {"metrics" => [{"type" => "External", "external" => {"metric" => {"name" => "m1-metric"}, "target" => {"type" => "Value", "value" => "1"}}, "resource" => "__delete__", "containerResource" => "__delete__", "object" => "__delete__", "pods" => "__delete__"}]}},
          "ObjectMetricSource" => {"spec" => {"metrics" => [{"type" => "Object", "object" => {"describedObject" => {"apiVersion" => "apps/v1", "kind" => "Deployment", "name" => "m1"}, "metric" => {"name" => "m1-metric"}, "target" => {"type" => "Value", "value" => "1"}}, "resource" => "__delete__", "containerResource" => "__delete__", "external" => "__delete__", "pods" => "__delete__"}]}},
          "PodsMetricSource" => {"spec" => {"metrics" => [{"type" => "Pods", "pods" => {"metric" => {"name" => "m1-metric"}, "target" => {"type" => "AverageValue", "averageValue" => "1"}}, "resource" => "__delete__", "containerResource" => "__delete__", "external" => "__delete__", "object" => "__delete__"}]}},
          "HPAScalingRules" => {"spec" => {"behavior" => {"scaleUp" => {"selectPolicy" => "Max", "stabilizationWindowSeconds" => 0, "policies" => [{"type" => "Pods", "value" => 1, "periodSeconds" => 15}]},
                                                           "scaleDown" => {"selectPolicy" => "Max", "stabilizationWindowSeconds" => 0, "policies" => [{"type" => "Pods", "value" => 1, "periodSeconds" => 15}]}}}},
          "HPAScalingPolicy" => {"spec" => {"behavior" => {"scaleUp" => {"selectPolicy" => "Max", "stabilizationWindowSeconds" => 0, "policies" => [{"type" => "Pods", "value" => 1, "periodSeconds" => 15}]},
                                                            "scaleDown" => {"selectPolicy" => "Max", "stabilizationWindowSeconds" => 0, "policies" => [{"type" => "Pods", "value" => 1, "periodSeconds" => 15}]}}}}
        }
      }
    },
    ["batch", "CronJob"] => {
      "source" => "pkg/apis/batch/validation/validation.go validateCronJobSpec",
      "fixture" => {"create" => {"spec" => {"schedule" => "*/5 * * * *",
                                            "jobTemplate" => {"spec" => {"template" => {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}]}}}}}}}
    },
    ["certificates.k8s.io", "CertificateSigningRequest"] => {
      "source" => "pkg/apis/certificates/validation/validation.go validateCertificateSigningRequest",
      "fixture" => {"create" => {"spec" => {"request" => "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlIU01Ib0NBUUF3R0RFV01CUUdBMVVFQXd3TmJURXRkbUZzYVdSaGRHbHZiakJaTUJNR0J5cUdTTTQ5QWdFRwpDQ3FHU000OUF3RUhBMElBQkJnTTgrYTA5dW1JeWp0S3BNSWNPMG52eU0rZGZYZlM5cG50WHBIblI2WnlJa3NKCmhKa0dDTjBCanZtQkF1NkVuKzFvSzV2NDZ6azBiNEpZd05EUk1lNmdBREFLQmdncWhrak9QUVFEQWdOSUFEQkYKQWlBWjlEeFYxZllxVTNMOFh0WFRBRmtwdFZMV1VNSlRMcWNkUEVEM1Mwb2xuZ0loQUk0NVhpZ0hMeHR1ZThoTQpzRkUrNHZQcnJiUmFsbzEwOUFUMmhVWWY5Y3VmCi0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=", "signerName" => "kubernetes.io/kube-apiserver-client", "usages" => ["client auth"]},
                                 "status" => {"conditions" => "__delete__"}},
                    "nested" => {"CertificateSigningRequestCondition" => {"status" => {"conditions" => [{"type" => "Approved", "status" => "True", "reason" => "M1", "message" => "m1"}]}}}}
    },
    ["certificates.k8s.io", "ClusterTrustBundle"] => {
      "source" => "pkg/apis/certificates/validation/validation.go ValidateClusterTrustBundle (at least one trust anchor)",
      "fixture" => {"create" => {"spec" => {"trustBundle" => "-----BEGIN CERTIFICATE-----\nMIIBMDCB2KADAgECAgEBMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBW0xLWNhMB4X\nDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowEDEOMAwGA1UEAwwFbTEtY2Ew\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQYDPPmtPbpiMo7SqTCHDtJ78jPnX13\n0vaZ7V6R50emciJLCYSZBgjdAY75gQLuhJ/taCub+Os5NG+CWMDQ0THuoyMwITAP\nBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBE\nAiBAbp8Cwl/cYjdstXSilQRFMU2/yJYTJRLdq/VpNqbaOwIgWEBo6M+NkG2Hxc/5\npftlNOCMiVqljZGQWVonROYFo1Q=\n-----END CERTIFICATE-----\n"}}}
    },
    ["coordination.k8s.io", "LeaseCandidate"] => {
      "source" => "pkg/apis/coordination/validation/validation.go ValidateLeaseCandidateSpec",
      "fixture" => {"create" => {"spec" => {"leaseName" => "m1-lease", "binaryVersion" => "1.36.2", "emulationVersion" => "1.36.2", "strategy" => "OldestEmulationVersion"}}}
    },
    ["", "PersistentVolume"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidatePersistentVolumeSpec (one volume source, capacity, access modes)",
      "fixture" => {
        "create" => {"spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"], "hostPath" => {"path" => "/m1"}}},
        "nested" => {
          "AWSElasticBlockStoreVolumeSource" => {"spec" => {"hostPath" => "__delete__", "awsElasticBlockStore" => {"volumeID" => "vol-m1"}}},
          "AzureDiskVolumeSource" => {"spec" => {"hostPath" => "__delete__", "azureDisk" => {"diskName" => "m1", "diskURI" => "https://m1.example.com/disks/m1.vhd"}}},
          "AzureFilePersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "azureFile" => {"secretName" => "m1", "shareName" => "m1"}}},
          "CephFSPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "cephfs" => {"monitors" => ["10.0.0.1:6789"]}}},
          "CinderPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "cinder" => {"volumeID" => "m1"}}},
          "CSIPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "csi" => {"driver" => "m1.example.com", "volumeHandle" => "m1", "controllerPublishSecretRef" => {"name" => "m1", "namespace" => "m1"}}}},
          "SecretReference" => {"spec" => {"hostPath" => "__delete__", "csi" => {"driver" => "m1.example.com", "volumeHandle" => "m1", "controllerPublishSecretRef" => {"name" => "m1", "namespace" => "m1"}, "nodeStageSecretRef" => {"name" => "m1", "namespace" => "m1"}, "nodePublishSecretRef" => {"name" => "m1", "namespace" => "m1"}, "controllerExpandSecretRef" => {"name" => "m1", "namespace" => "m1"}, "nodeExpandSecretRef" => {"name" => "m1", "namespace" => "m1"}}}},
          "VolumeNodeAffinity" => {"spec" => {"nodeAffinity" => {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}}},
          "FCVolumeSource" => {"spec" => {"hostPath" => "__delete__", "fc" => {"targetWWNs" => ["50060e801049cfd1"], "lun" => 0}}},
          "FlexPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "flexVolume" => {"driver" => "m1.example.com/driver"}}},
          "FlockerVolumeSource" => {"spec" => {"hostPath" => "__delete__", "flocker" => {"datasetName" => "m1", "datasetUUID" => "__delete__"}}},
          "GCEPersistentDiskVolumeSource" => {"spec" => {"hostPath" => "__delete__", "gcePersistentDisk" => {"pdName" => "m1"}}},
          "GlusterfsPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "glusterfs" => {"endpoints" => "m1", "path" => "m1"}}},
          "ISCSIPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "iscsi" => {"targetPortal" => "10.0.0.1:3260", "iqn" => "iqn.2026-01.com.example:m1", "lun" => 0}}},
          "LocalVolumeSource" => {"spec" => {"hostPath" => "__delete__", "local" => {"path" => "/m1"}, "nodeAffinity" => {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}}},
          "NFSVolumeSource" => {"spec" => {"hostPath" => "__delete__", "nfs" => {"server" => "10.0.0.1", "path" => "/m1"}}},
          "PhotonPersistentDiskVolumeSource" => {"spec" => {"hostPath" => "__delete__", "photonPersistentDisk" => {"pdID" => "m1"}}},
          "PortworxVolumeSource" => {"spec" => {"hostPath" => "__delete__", "portworxVolume" => {"volumeID" => "m1"}}},
          "QuobyteVolumeSource" => {"spec" => {"hostPath" => "__delete__", "quobyte" => {"registry" => "10.0.0.1:7861", "volume" => "m1"}}},
          "RBDPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "rbd" => {"monitors" => ["10.0.0.1:6789"], "image" => "m1"}}},
          "ScaleIOPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "scaleIO" => {"gateway" => "https://m1.example.com", "system" => "m1", "volumeName" => "m1", "secretRef" => {"name" => "m1", "namespace" => "m1"}}}},
          "StorageOSPersistentVolumeSource" => {"spec" => {"hostPath" => "__delete__", "storageos" => {"volumeName" => "m1"}}},
          "VsphereVirtualDiskVolumeSource" => {"spec" => {"hostPath" => "__delete__", "vsphereVolume" => {"volumePath" => "[ds] m1.vmdk"}}}
        }
      }
    },
    ["", "Service"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidateService (ports required)",
      "fixture" => {"create" => {"spec" => {"ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP"}]}}}
    },
    ["", "Node"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidateNodeUpdate (status.config sources)",
      "fixture" => {
        "nested" => {
          "NodeConfigSource" => {"spec" => {"configSource" => {"configMap" => {"namespace" => "kube-system", "name" => "m1", "kubeletConfigKey" => "kubelet"}}}},
          "ConfigMapNodeConfigSource" => {"spec" => {"configSource" => {"configMap" => {"namespace" => "kube-system", "name" => "m1", "kubeletConfigKey" => "kubelet"}}},
                                          "status" => {"config" => {"active" => {"configMap" => {"namespace" => "kube-system", "name" => "m1", "kubeletConfigKey" => "kubelet", "uid" => "11111111-1111-4111-8111-111111111111", "resourceVersion" => "1"}}}}},
          "Taint" => {"spec" => {"taints" => [{"key" => "m1.example.com/taint", "effect" => "NoSchedule"}]}}
        }
      }
    },
    ["", "Endpoints"] => {
      "source" => "pkg/apis/core/validation/validation.go validateEndpointAddress",
      "fixture" => {"create" => {"subsets" => [{"addresses" => [{"ip" => "10.0.0.1"}], "ports" => [{"port" => 80}]}]}}
    },
    ["", "PersistentVolumeClaim"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidatePersistentVolumeClaimSpec",
      "fixture" => {"create" => {"spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}},
                    "nested" => {"TypedLocalObjectReference" => {"spec" => {"dataSource" => {"apiGroup" => "__delete__", "kind" => "PersistentVolumeClaim", "name" => "m1"}}},
                                 "TypedObjectReference" => {"spec" => {"dataSourceRef" => {"apiGroup" => "__delete__", "kind" => "PersistentVolumeClaim", "name" => "m1", "namespace" => "__delete__"}}}}}
    },
    ["", "PodTemplate"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidatePodTemplateSpec",
      "fixture" => {"create" => {"template" => {"spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}], "restartPolicy" => "Always"}}}}
    },
    ["", "ReplicationController"] => {
      "source" => "pkg/apis/core/validation/validation.go ValidateReplicationControllerSpec",
      "fixture" => {"create" => {"spec" => {"selector" => {"app" => "m1"}, "template" => {"metadata" => {"labels" => {"app" => "m1"}}, "spec" => {"containers" => [{"name" => "m1", "image" => "m1.example.com/pause:1"}], "restartPolicy" => "Always"}}}}}
    },
    ["", "ResourceQuota"] => {
      "source" => "pkg/apis/core/validation/validation.go validateScopedResourceSelectorRequirement",
      "fixture" => {"nested" => {"ScopedResourceSelectorRequirement" => {"spec" => {"scopeSelector" => {"matchExpressions" => [{"scopeName" => "PriorityClass", "operator" => "In", "values" => ["m1"]}]}}}}}
    },
    ["storage.k8s.io", "StorageClass"] => {
      "source" => "pkg/apis/storage/validation/validation.go validateAllowedTopologies",
      "fixture" => {"nested" => {"TopologySelectorTerm" => {"allowedTopologies" => [{"matchLabelExpressions" => [{"key" => "topology.kubernetes.io/zone", "values" => ["m1"]}]}]},
                                 "TopologySelectorLabelRequirement" => {"allowedTopologies" => [{"matchLabelExpressions" => [{"key" => "topology.kubernetes.io/zone", "values" => ["m1"]}]}]}}}
    },
    ["discovery.k8s.io", "EndpointSlice"] => {
      "source" => "pkg/apis/discovery/validation/validation.go validateAddressType",
      "fixture" => {"create" => {"addressType" => "IPv4", "endpoints" => [{"addresses" => ["10.0.0.1"]}], "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP"}]},
                    "nested" => {"ForZone" => {"endpoints" => [{"addresses" => ["10.0.0.1"], "hints" => {"forZones" => [{"name" => "m1-zone"}]}}]},
                                 "ForNode" => {"endpoints" => [{"addresses" => ["10.0.0.1"], "hints" => {"forNodes" => [{"name" => "m1-node"}]}}]},
                                 "EndpointHints" => {"endpoints" => [{"addresses" => ["10.0.0.1"], "hints" => {"forZones" => [{"name" => "m1-zone"}]}}]}}}
    },
    ["flowcontrol.apiserver.k8s.io", "PriorityLevelConfiguration"] => {
      "source" => "pkg/apis/flowcontrol/validation/validation.go ValidatePriorityLevelConfigurationSpec",
      "fixture" => {
        # Only the mandatory "exempt" level may be of type Exempt.
        "create" => {"spec" => {"type" => "Limited", "exempt" => "__delete__", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Reject", "queuing" => "__delete__"}}}},
        "nested" => {
          "QueuingConfiguration" => {"spec" => {"type" => "Limited", "exempt" => "__delete__", "limited" => {"nominalConcurrencyShares" => 1, "limitResponse" => {"type" => "Queue", "queuing" => {"queues" => 64, "handSize" => 8, "queueLengthLimit" => 50}}}}},
          "ExemptPriorityLevelConfiguration" => {"metadata" => {"name" => "exempt"}, "spec" => {"type" => "Exempt", "limited" => "__delete__", "exempt" => {"nominalConcurrencyShares" => 0, "lendablePercent" => 0}}},
          "PriorityLevelConfigurationCondition" => {"status" => {"conditions" => [{"type" => "Ready", "status" => "True", "reason" => "M1", "message" => "m1"}]}}
        }
      }
    },
    ["flowcontrol.apiserver.k8s.io", "FlowSchema"] => {
      "source" => "pkg/apis/flowcontrol/validation/validation.go ValidateFlowSchemaSpec",
      "fixture" => {
        "create" => {"spec" => {"priorityLevelConfiguration" => {"name" => "m1-level"}, "distinguisherMethod" => {"type" => "ByUser"},
                                "rules" => [{"subjects" => [{"kind" => "User", "user" => {"name" => "m1"}, "group" => "__delete__", "serviceAccount" => "__delete__"}],
                                             "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "clusterScope" => true}]}]}},
        "nested" => {
          "GroupSubject" => {"spec" => {"rules" => [{"subjects" => [{"kind" => "Group", "user" => "__delete__", "serviceAccount" => "__delete__", "group" => {"name" => "m1"}}]}]}},
          "ServiceAccountSubject" => {"spec" => {"rules" => [{"subjects" => [{"kind" => "ServiceAccount", "user" => "__delete__", "group" => "__delete__", "serviceAccount" => {"namespace" => "m1", "name" => "m1"}}]}]}},
          "NonResourcePolicyRule" => {"spec" => {"rules" => [{"nonResourceRules" => [{"verbs" => ["*"], "nonResourceURLs" => ["/healthz"]}]}]}},
          "FlowSchemaCondition" => {"status" => {"conditions" => [{"type" => "Dangling", "status" => "False", "reason" => "M1", "message" => "m1"}]}}
        }
      }
    },
    ["networking.k8s.io", "Ingress"] => {
      "source" => "pkg/apis/networking/validation/validation.go validateIngressSpec",
      "fixture" => {
        "create" => {"spec" => {"defaultBackend" => {"service" => {"name" => "m1", "port" => {"number" => 80, "name" => "__delete__"}}, "resource" => "__delete__"}}},
        "nested" => {
          "IngressRule" => {"spec" => {"defaultBackend" => "__delete__", "rules" => [{"host" => "m1.example.com", "http" => {"paths" => [{"path" => "/m1", "pathType" => "Prefix", "backend" => {"service" => {"name" => "m1", "port" => {"number" => 80}}}}]}}]}},
          "HTTPIngressRuleValue" => {"spec" => {"defaultBackend" => "__delete__", "rules" => [{"host" => "m1.example.com", "http" => {"paths" => [{"path" => "/m1", "pathType" => "Prefix", "backend" => {"service" => {"name" => "m1", "port" => {"number" => 80}}}}]}}]}},
          "HTTPIngressPath" => {"spec" => {"defaultBackend" => "__delete__", "rules" => [{"host" => "m1.example.com", "http" => {"paths" => [{"path" => "/m1", "pathType" => "Prefix", "backend" => {"service" => {"name" => "m1", "port" => {"number" => 80}}}}]}}]}},
          "IngressTLS" => {"spec" => {"tls" => [{"hosts" => ["m1.example.com"], "secretName" => "m1-tls"}]}},
          "TypedLocalObjectReference" => {"spec" => {"defaultBackend" => {"service" => "__delete__", "resource" => {"apiGroup" => "m1.example.com", "kind" => "StorageBucket", "name" => "m1"}}}}
        }
      }
    },
    ["networking.k8s.io", "NetworkPolicy"] => {
      "source" => "pkg/apis/networking/validation/validation.go ValidateIPBlock",
      "fixture" => {"nested" => {"IPBlock" => {"spec" => {"egress" => [{"to" => [{"ipBlock" => {"cidr" => "10.0.0.0/24"}}]}]}},
                                 "NetworkPolicyPeer" => {"spec" => {"egress" => [{"to" => [{"ipBlock" => {"cidr" => "10.0.0.0/24"}}]}]}}}}
    },
    ["networking.k8s.io", "IngressClass"] => {
      "source" => "pkg/apis/networking/validation/validation.go ValidateIngressClassSpec",
      "fixture" => {"create" => {"spec" => {"controller" => "m1.example.com/ingress"}},
                    "nested" => {"IngressClassParametersReference" => {"spec" => {"parameters" => {"apiGroup" => "m1.example.com", "kind" => "IngressParameters", "name" => "m1", "scope" => "Cluster", "namespace" => "__delete__"}}}}}
    },
    ["networking.k8s.io", "ServiceCIDR"] => {
      "source" => "pkg/apis/networking/validation/validation.go ValidateServiceCIDR",
      "fixture" => {"create" => {"spec" => {"cidrs" => ["10.0.0.0/24"]}}}
    },
    ["rbac.authorization.k8s.io", "ClusterRole"] => {
      "source" => "pkg/apis/rbac/validation/validation.go ValidateClusterRole (aggregationRule)",
      "fixture" => {"nested" => {"AggregationRule" => {"aggregationRule" => {"clusterRoleSelectors" => [{"matchLabels" => {"m1" => "true"}}]}},
                                 "PolicyRule" => {"rules" => [{"verbs" => ["get"], "apiGroups" => [""], "resources" => ["pods"]}]}}}
    },
    ["rbac.authorization.k8s.io", "ClusterRoleBinding"] => {
      "source" => "pkg/apis/rbac/validation/validation.go ValidateClusterRoleBinding (roleRef)",
      "fixture" => {"create" => {"roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "ClusterRole", "name" => "m1"}, "subjects" => [{"kind" => "User", "apiGroup" => "rbac.authorization.k8s.io", "name" => "m1"}]}}
    },
    ["rbac.authorization.k8s.io", "RoleBinding"] => {
      "source" => "pkg/apis/rbac/validation/validation.go ValidateRoleBinding (roleRef)",
      "fixture" => {"create" => {"roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "Role", "name" => "m1"}}}
    },
    ["resource.k8s.io", "DeviceClass"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateCELSelector",
      "fixture" => {"nested" => {"CELDeviceSelector" => {"spec" => {"selectors" => [{"cel" => {"expression" => "true"}}]}},
                                 "DeviceSelector" => {"spec" => {"selectors" => [{"cel" => {"expression" => "true"}}]}},
                                 "DeviceClassConfiguration" => {"spec" => {"config" => [{"opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}}
    },
    ["resource.k8s.io", "ResourceClaim"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateDeviceClaim",
      "fixture" => {
        "create" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}]}}},
        "nested" => {
          "DeviceSubRequest" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class"}]}]}}},
          "DeviceToleration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "tolerations" => [{"key" => "m1.example.com/taint", "operator" => "Exists", "effect" => "NoSchedule"}]}]}]}}},
          "CapacityRequirements" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "capacity" => {"requests" => {"memory" => "1Gi"}}}]}]}}},
          "DeviceConstraint" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "constraints" => [{"requests" => ["m1-request"], "matchAttribute" => "m1.example.com/attr", "distinctAttribute" => "__delete__"}]}}},
          "DeviceClaimConfiguration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}},
          "OpaqueDeviceConfiguration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}
        }
      }
    },
    ["resource.k8s.io", "ResourceClaimTemplate"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateDeviceClaim",
      "fixture" => {
        "create" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}]}}}},
        "nested" => {
          "DeviceSubRequest" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class"}]}]}}}},
          "DeviceToleration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "tolerations" => [{"key" => "m1.example.com/taint", "operator" => "Exists", "effect" => "NoSchedule"}]}]}]}}}},
          "CapacityRequirements" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "exactly" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "capacity" => {"requests" => {"memory" => "1Gi"}}}]}]}}}},
          "DeviceConstraint" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "constraints" => [{"requests" => ["m1-request"], "matchAttribute" => "m1.example.com/attr", "distinctAttribute" => "__delete__"}]}}}},
          "DeviceClaimConfiguration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}},
          "OpaqueDeviceConfiguration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "firstAvailable" => "__delete__", "exactly" => {"deviceClassName" => "m1-class"}}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}}
        }
      }
    },
    ["resource.k8s.io", "v1beta1", "ResourceClaim"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateDeviceClaim (v1beta1 requests carry the exact request fields inline)",
      "fixture" => {
        "create" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}]}}},
        "nested" => {
          "DeviceSubRequest" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class"}]}]}}},
          "DeviceToleration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "tolerations" => [{"key" => "m1.example.com/taint", "operator" => "Exists", "effect" => "NoSchedule"}]}]}]}}},
          "CapacityRequirements" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "capacity" => {"requests" => {"memory" => "1Gi"}}}]}]}}},
          "DeviceConstraint" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "constraints" => [{"requests" => ["m1-request"], "matchAttribute" => "m1.example.com/attr", "distinctAttribute" => "__delete__"}]}}},
          "DeviceClaimConfiguration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}},
          "OpaqueDeviceConfiguration" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}
        }
      }
    },
    ["resource.k8s.io", "v1beta1", "ResourceClaimTemplate"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateDeviceClaim (v1beta1 requests carry the exact request fields inline)",
      "fixture" => {
        "create" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}]}}}},
        "nested" => {
          "DeviceSubRequest" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class"}]}]}}}},
          "DeviceToleration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "tolerations" => [{"key" => "m1.example.com/taint", "operator" => "Exists", "effect" => "NoSchedule"}]}]}]}}}},
          "CapacityRequirements" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "__delete__", "allocationMode" => "__delete__", "count" => "__delete__", "selectors" => "__delete__", "tolerations" => "__delete__", "capacity" => "__delete__", "adminAccess" => "__delete__", "firstAvailable" => [{"name" => "m1-sub", "deviceClassName" => "m1-class", "capacity" => {"requests" => {"memory" => "1Gi"}}}]}]}}}},
          "DeviceConstraint" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "constraints" => [{"requests" => ["m1-request"], "matchAttribute" => "m1.example.com/attr", "distinctAttribute" => "__delete__"}]}}}},
          "DeviceClaimConfiguration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}},
          "OpaqueDeviceConfiguration" => {"spec" => {"spec" => {"devices" => {"requests" => [{"name" => "m1-request", "deviceClassName" => "m1-class", "firstAvailable" => "__delete__"}], "config" => [{"requests" => ["m1-request"], "opaque" => {"driver" => "m1.example.com", "parameters" => {"m1" => true}}}]}}}}
        }
      }
    },
    ["resource.k8s.io", "ResourceSlice"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateResourceSliceSpec",
      "fixture" => {
        "create" => {"spec" => {"nodeName" => "m1-node", "nodeSelector" => "__delete__", "allNodes" => "__delete__", "perDeviceNodeSelection" => "__delete__",
                                "driver" => "m1.example.com", "pool" => {"name" => "m1-pool", "generation" => 1, "resourceSliceCount" => 1}}},
        "nested" => {
          "NodeSelector" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "NodeSelectorTerm" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "NodeSelectorRequirement" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "Device" => {"spec" => {"devices" => [{"name" => "m1-device"}]}},
          "DeviceTaint" => {"spec" => {"devices" => [{"name" => "m1-device", "taints" => [{"key" => "m1.example.com/taint", "effect" => "NoSchedule"}]}]}},
          "DeviceCapacity" => {"spec" => {"devices" => [{"name" => "m1-device", "allowMultipleAllocations" => true}]}},
          "CapacityRequestPolicy" => {"spec" => {"devices" => [{"name" => "m1-device", "allowMultipleAllocations" => true, "capacity" => {"m1" => {"value" => "8", "requestPolicy" => {"default" => "1", "validValues" => "__delete__", "validRange" => {"min" => "1", "max" => "8", "step" => "1"}}}}}]}},
          "CapacityRequestPolicyRange" => {"spec" => {"devices" => [{"name" => "m1-device", "allowMultipleAllocations" => true, "capacity" => {"m1" => {"value" => "8", "requestPolicy" => {"default" => "1", "validValues" => "__delete__", "validRange" => {"min" => "1", "max" => "8", "step" => "1"}}}}}]}},
          "Counter" => {"spec" => {"devices" => "__delete__", "sharedCounters" => [{"name" => "m1-counters", "counters" => {"m1" => {"value" => "8"}}}]}},
          "CounterSet" => {"spec" => {"devices" => "__delete__", "sharedCounters" => [{"name" => "m1-counters", "counters" => {"m1" => {"value" => "8"}}}]}},
          "DeviceCounterConsumption" => {"spec" => {"sharedCounters" => "__delete__", "devices" => [{"name" => "m1-device", "consumesCounters" => [{"counterSet" => "m1-counters", "counters" => {"m1" => {"value" => "1"}}}]}]}},
          "DeviceAttribute" => {"spec" => {"devices" => [{"name" => "m1-device", "attributes" => {"m1" => {"string" => "m1", "bool" => "__delete__", "int" => "__delete__", "version" => "__delete__"}}}]}},
          "NodeAllocatableResourceMapping" => {"spec" => {"devices" => [{"name" => "m1-device"}]}},
          "BasicDevice" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"allowMultipleAllocations" => true}}]}}
        }
      }
    },
    ["resource.k8s.io", "v1beta1", "ResourceSlice"] => {
      "source" => "pkg/apis/resource/validation/validation.go validateResourceSliceSpec (v1beta1 devices carry a basic section)",
      "fixture" => {
        "create" => {"spec" => {"nodeName" => "m1-node", "nodeSelector" => "__delete__", "allNodes" => "__delete__", "perDeviceNodeSelection" => "__delete__",
                                "driver" => "m1.example.com", "pool" => {"name" => "m1-pool", "generation" => 1, "resourceSliceCount" => 1}}},
        "nested" => {
          "NodeSelector" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "NodeSelectorTerm" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "NodeSelectorRequirement" => {"spec" => {"nodeName" => "__delete__", "nodeSelector" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "kubernetes.io/hostname", "operator" => "In", "values" => ["m1"]}]}]}}},
          "Device" => {"spec" => {"devices" => [{"name" => "m1-device"}]}},
          "BasicDevice" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"allowMultipleAllocations" => true}}]}},
          "DeviceTaint" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"taints" => [{"key" => "m1.example.com/taint", "effect" => "NoSchedule"}]}}]}},
          "DeviceCapacity" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"allowMultipleAllocations" => true}}]}},
          "CapacityRequestPolicy" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"allowMultipleAllocations" => true, "capacity" => {"m1" => {"value" => "8", "requestPolicy" => {"default" => "1", "validValues" => "__delete__", "validRange" => {"min" => "1", "max" => "8", "step" => "1"}}}}}}]}},
          "CapacityRequestPolicyRange" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"allowMultipleAllocations" => true, "capacity" => {"m1" => {"value" => "8", "requestPolicy" => {"default" => "1", "validValues" => "__delete__", "validRange" => {"min" => "1", "max" => "8", "step" => "1"}}}}}}]}},
          "Counter" => {"spec" => {"devices" => "__delete__", "sharedCounters" => [{"name" => "m1-counters", "counters" => {"m1" => {"value" => "8"}}}]}},
          "CounterSet" => {"spec" => {"devices" => "__delete__", "sharedCounters" => [{"name" => "m1-counters", "counters" => {"m1" => {"value" => "8"}}}]}},
          "DeviceCounterConsumption" => {"spec" => {"sharedCounters" => "__delete__", "devices" => [{"name" => "m1-device", "basic" => {"consumesCounters" => [{"counterSet" => "m1-counters", "counters" => {"m1" => {"value" => "1"}}}]}}]}},
          "DeviceAttribute" => {"spec" => {"devices" => [{"name" => "m1-device", "basic" => {"attributes" => {"m1" => {"string" => "m1", "bool" => "__delete__", "int" => "__delete__", "version" => "__delete__"}}}}]}},
          "NodeAllocatableResourceMapping" => {"spec" => {"devices" => [{"name" => "m1-device"}]}}
        }
      }
    },
    ["storage.k8s.io", "VolumeAttachment"] => {
      "source" => "pkg/apis/storage/validation/validation.go validateVolumeAttachmentSource",
      "fixture" => {"create" => {"spec" => {"attacher" => "m1.example.com", "nodeName" => "m1-node", "source" => {"persistentVolumeName" => "m1-pv", "inlineVolumeSpec" => "__delete__"}}},
                    "nested" => {"PersistentVolumeSpec" => {"spec" => {"source" => {"persistentVolumeName" => "__delete__", "inlineVolumeSpec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"], "csi" => {"driver" => "m1.example.com", "volumeHandle" => "m1"}}}}}}}
    },
    ["storage.k8s.io", "VolumeAttributesClass"] => {
      "source" => "pkg/apis/storage/validation/validation.go ValidateVolumeAttributesClass",
      "fixture" => {"create" => {"driverName" => "m1.example.com", "parameters" => {"m1" => "true"}}}
    },
    ["storage.k8s.io", "CSINode"] => {
      "source" => "pkg/apis/storage/validation/validation.go validateCSINodeDriver",
      "fixture" => {"create" => {"spec" => {"drivers" => [{"name" => "m1.example.com", "nodeID" => "m1-node"}]}}}
    },
    ["storagemigration.k8s.io", "StorageVersionMigration"] => {
      "source" => "pkg/apis/storagemigration/validation/validation.go ValidateStorageVersionMigration",
      "fixture" => {"create" => {"spec" => {"resource" => {"group" => "apps", "resource" => "deployments"}}}}
    },
    ["storage.k8s.io", "CSIStorageCapacity"] => {
      "source" => "pkg/apis/storage/validation/validation.go ValidateCSIStorageCapacity (nodeTopology)",
      "fixture" => {"nested" => {"LabelSelectorRequirement" => {"nodeTopology" => {"matchExpressions" => [{"key" => "topology.kubernetes.io/zone", "operator" => "In", "values" => ["m1"]}]}}}}
    },
    ["admissionregistration.k8s.io", "MutatingWebhookConfiguration"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateMutatingWebhook",
      "fixture" => {"create" => {"webhooks" => [{"name" => "hook.m1.example.com", "admissionReviewVersions" => ["v1"], "sideEffects" => "None", "clientConfig" => {"url" => "__delete__", "service" => {"name" => "m1", "namespace" => "m1", "path" => "/hook", "port" => 443}}, "rules" => [{"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["pods"]}], "matchConditions" => [{"name" => "m1-condition", "expression" => "true"}]}]}}
    },
    ["admissionregistration.k8s.io", "ValidatingWebhookConfiguration"] => {
      "source" => "pkg/apis/admissionregistration/validation/validation.go validateValidatingWebhook",
      "fixture" => {"create" => {"webhooks" => [{"name" => "hook.m1.example.com", "admissionReviewVersions" => ["v1"], "sideEffects" => "None", "clientConfig" => {"url" => "__delete__", "service" => {"name" => "m1", "namespace" => "m1", "path" => "/hook", "port" => 443}}, "rules" => [{"apiGroups" => [""], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["pods"]}], "matchConditions" => [{"name" => "m1-condition", "expression" => "true"}]}]}}
    },
    ["", "Event"] => {
      "source" => "pkg/apis/core/validation/events.go legacyValidateEvent (core/v1 requests skip ObjectMeta validation)",
      "fixture" => {
        "create" => {"involvedObject" => {"kind" => "Pod", "name" => "m1", "namespace" => "m1-validation"}},
        "invalid" => {"involvedObject" => {"namespace" => "m1-other"}},
        # An Event with eventTime set runs the modern field requirements.
        "nested" => {"MicroTime" => {"create" => {"action" => "M1Action", "reason" => "M1Reason", "reportingComponent" => "m1.example.com/controller", "reportingInstance" => "m1-instance"},
                                     "invalid" => {"action" => ""}}}
      },
      # legacyValidateEvent still rejects the empty namespace of the zero
      # object (IsDNS1123Subdomain("")).
      "expectations" => {"create" => true, "invalid" => false, "update" => true, "missing" => false}
    },
    ["events.k8s.io", "Event"] => {
      "source" => "pkg/apis/core/validation/events.go ValidateEventCreate (events.k8s.io requests use the strict path)",
      "fixture" => {
        "create" => {
          "eventTime" => "2026-01-01T00:00:00.000000Z", "type" => "Normal", "action" => "M1Action", "reason" => "M1Reason",
          "reportingController" => "m1.example.com/controller", "reportingInstance" => "m1-instance",
          "regarding" => {"kind" => "Pod", "name" => "m1", "namespace" => "m1-validation"},
          "series" => {"count" => 2, "lastObservedTime" => "2026-01-01T00:00:00.000000Z"},
          "deprecatedFirstTimestamp" => "__delete__", "deprecatedLastTimestamp" => "__delete__", "deprecatedCount" => "__delete__", "deprecatedSource" => "__delete__"
        }
      }
    }
  }.freeze

  module_function

  # A fixture entry is keyed by [group, kind]; a [group, version, kind] entry
  # overrides it for one served version whose wire shape differs.
  def strategy_fixture_for(owner)
    gvk = owner["owner_gvk"]
    return nil unless gvk.is_a?(Hash)

    STRATEGY_FIXTURES[[gvk.fetch("group", ""), gvk.fetch("version"), gvk.fetch("kind")]] ||
      STRATEGY_FIXTURES[[gvk.fetch("group", ""), gvk.fetch("kind")]]
  end

  def compare(source_root:, requests:, go: ENV.fetch("GO", "go"))
    source_root = ::File.expand_path(source_root)
    verify_source!(source_root)
    normalized = normalize_requests(requests)
    raise OracleError, "Kubernetes validation oracle request inventory is empty" if normalized.empty?

    mappings = normalized.filter_map { |request| request["validation_mapping"] }.uniq
    source, inventory = go_source(normalized, mappings)
    response, go_version = execute_go(
      go: go,
      source_root: source_root,
      source: source,
      requests: normalized
    )
    expected_ids = normalized.map { |entry| entry.fetch("id") }.sort
    actual_ids = response.map { |entry| entry.fetch("id") }.sort
    unless actual_ids == expected_ids && actual_ids.uniq.length == actual_ids.length
      raise OracleError, "Kubernetes validation oracle response inventory does not match requests"
    end

    # The Go runner only needs the strategy import and owner GVK to execute.
    # Reattach the Ruby-side graph mapping here so every result retains the
    # source-anchored owner, nested target path, and N/A ledger reason.
    request_by_id = normalized.to_h { |request| [request.fetch("id"), request] }
    response = response.map do |entry|
      request = request_by_id.fetch(entry.fetch("id"))
      mapping = request["validation_mapping"]
      if mapping
        entry.merge(
          "applicable" => true,
          "owner_schema" => mapping.fetch("owner_schema"),
          "target_path" => mapping.fetch("target_path"),
          "source_paths" => mapping.fetch("source_paths"),
          "mode" => entry["mode"] || mapping["validation_mode"],
          "evidence" => entry["evidence"] || mapping["evidence"],
          # The Go runner reports only what it executed; the source-anchored
          # collaborator inventory (authorizer, resolver, ...) is Ruby-side.
          "collaborators" => Array(mapping["collaborators"])
        )
      else
        entry.merge(
          "applicable" => false,
          "reason" => request.fetch("validation_reason"),
          "source_paths" => request.fetch("validation_source_paths")
        )
      end
    end

    applicable_count = response.count { |entry| entry.fetch("applicable") == true }
    not_applicable_count = response.length - applicable_count
    validation_criterion = {
      "status" => not_applicable_count.zero? ? "COMPLETE" : "INCOMPLETE",
      "applicable_count" => applicable_count,
      "not_applicable_count" => not_applicable_count,
      "ledger" => response.sort_by { |entry| entry.fetch("id") }.map do |entry|
        {
          "id" => entry.fetch("id"),
          "applicable" => entry.fetch("applicable"),
          "mode" => entry["mode"],
          "owner_schema" => entry["owner_schema"],
          "evidence" => entry["evidence"],
          "collaborators" => Array(entry["collaborators"]),
          "reason" => entry["reason"],
          "source_paths" => Array(entry["source_paths"])
        }
      end
    }

    runner_sha256 = Digest::SHA256.hexdigest(source)
    request_seed_sha256 = Digest::SHA256.hexdigest(JSON.generate(normalized))
    provenance = {
      "kind" => M1Gate::KUBERNETES_SEMANTICS_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "pinned kube-apiserver REST create/update strategies",
      "source" => {
        "version" => KUBERNETES_VERSION,
        "commit" => SOURCE_COMMIT,
        "tag" => KUBERNETES_VERSION,
        "root" => source_root,
        "tree_clean" => true,
        "strategy_inventory_count" => inventory.length,
        "strategy_inventory_sha256" => Digest::SHA256.hexdigest(JSON.generate(inventory))
      },
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request_seed_sha256
    }
    provenance["provenance_sha256"] = M1Gate.canonical_document_digest(provenance)

    {
      "executed" => true,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => SOURCE_COMMIT,
      "source_tag" => KUBERNETES_VERSION,
      "source_root" => source_root,
      "source_tree_clean" => true,
      "go_version" => go_version,
      "helper_sha256" => runner_sha256,
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request_seed_sha256,
      "mapping_sha256" => Digest::SHA256.hexdigest(JSON.generate(inventory)),
      "comparison_count" => response.length,
      "missing_comparison_count" => 0,
      "implementation" => "pinned kube-apiserver REST create/update strategies",
      "validation_observable" => "RESTCreateUpdateStrategy PrepareForCreate/Validate and PrepareForUpdate/ValidateUpdate",
      "applicability_policy" => "N/A is emitted only when the pinned source has no REST create/update strategy path to the descriptor; each reason cites the scanned source package",
      "validation_criterion" => validation_criterion,
      "provenance" => provenance,
      "comparisons" => response.sort_by { |entry| entry.fetch("id") }
    }
  end

  # Derive a deterministic owner and fixture path for every generated schema.
  # A generated descriptor is validation-applicable only when this source
  # checkout provides an executable REST strategy owner.  Concrete protocol
  # structs are intentionally not treated as validation endpoints: decoding a
  # struct (and observing that it implements runtime.Object) does not prove
  # that kube-apiserver validates it on create/update.
  def map_types(source_root:, types:)
    source_root = ::File.expand_path(source_root)
    verify_source!(source_root)
    entries = strategy_inventory(source_root)
    by_schema = Array(types).to_h { |type| [type.fetch("schema"), type] }
    all_roots = entries.flat_map do |entry|
      candidates = by_schema.values.select do |type|
        next false unless type.fetch("schema").end_with?(".#{entry.fetch("internal_type")}")

        type.fetch("schema").start_with?("#{entry.fetch("schema_prefix") }.") &&
          type.fetch("gvks").any? do |gvk|
            !%w[DeleteOptions WatchEvent Status].include?(gvk.fetch("kind"))
          end
      end
      candidates.filter_map do |candidate|
        owner_gvk = preferred_gvk(candidate)
        next unless owner_gvk

        candidate_version = owner_gvk.fetch("version")
        version_import = entry.fetch("version_import_template").sub("%{version}", candidate_version)
        next unless entry.fetch("version_imports").include?(version_import)

        external_package = entry.fetch("external_package_template").sub("%{version}", candidate_version)
        entry.merge(
          "owner_schema" => candidate.fetch("schema"),
          "owner_type" => candidate.fetch("schema"),
          "owner_gvk" => owner_gvk,
          "version_import" => version_import,
          "external_package" => external_package,
          "internal_source_path" => source_path_for_import(version_import),
          "validation_mapping" => {
            "strategy_import" => entry.fetch("strategy_import"),
            "strategy_source_path" => entry.fetch("strategy_source_path"),
            "internal_package" => entry.fetch("internal_package"),
            "internal_type" => entry.fetch("internal_type"),
            "version_import" => version_import,
            "external_package" => external_package,
            "external_type" => entry.fetch("internal_type"),
            "owner_schema" => candidate.fetch("schema")
          }
        )
      end
    end
    strategy_roots = all_roots.select do |entry|
      entry.fetch("strategy_mode") != "protocol" && entry.fetch("constructor_safe", true)
    end
    handler_roots = HANDLER_ROOTS.filter_map do |schema, spec|
      next unless by_schema.key?(schema)

      spec.merge(
        "strategy_mode" => "handler",
        "owner_schema" => schema,
        "owner_type" => schema,
        "owner_gvk" => spec.fetch("gvk"),
        "handler_key" => schema,
        "strategy_import" => spec.fetch("validation_import"),
        "strategy_pointer" => false,
        "constructor_arity" => 0,
        "constructor_arguments" => [],
        "constructor_safe" => true,
        "strategy_source_path" => spec.fetch("handler_source_path"),
        "internal_source_path" => spec["internal_package"] ? source_path_for_import(spec.fetch("version_import")) : spec.fetch("validation_source_path"),
        "source_paths" => [spec.fetch("handler_source_path"), spec.fetch("validation_source_path")].uniq
      )
    end
    rest_roots = REST_ENDPOINT_ROOTS.filter_map do |schema, spec|
      next unless by_schema.key?(schema)

      {
        "strategy_mode" => "rest_endpoint",
        "owner_schema" => schema, "owner_type" => schema, "owner_gvk" => spec.fetch("gvk"),
        "strategy_import" => nil, "strategy_pointer" => false, "constructor_arity" => 0, "constructor_arguments" => [],
        "constructor_safe" => true, "namespace_scoped" => false,
        "strategy_source_path" => spec.fetch("handler_source_path"), "internal_source_path" => spec.fetch("handler_source_path"),
        "internal_package" => nil, "internal_type" => schema.split(".").last, "version_import" => nil, "external_package" => nil,
        "source_paths" => [spec.fetch("handler_source_path")],
        "evidence" => {"report" => "api-differential", "operations" => spec.fetch("api_operations")}
      }
    end
    response_roots = RESPONSE_ROOTS.filter_map do |schema, spec|
      next unless by_schema.key?(schema)

      {
        "strategy_mode" => "response",
        "owner_schema" => schema, "owner_type" => schema, "owner_gvk" => by_schema.fetch(schema).fetch("gvks").first,
        "strategy_import" => nil, "strategy_pointer" => false, "constructor_arity" => 0, "constructor_arguments" => [],
        "constructor_safe" => true, "namespace_scoped" => false,
        "strategy_source_path" => spec.fetch("source_path"), "internal_source_path" => spec.fetch("source_path"),
        "internal_package" => nil, "internal_type" => schema.split(".").last, "version_import" => nil, "external_package" => nil,
        "source_paths" => [spec.fetch("source_path")],
        "evidence" => {"report" => "api-differential", "operations" => spec.fetch("api_operations")}
      }
    end
    edges = schema_edges(by_schema)
    assign_owners = lambda do |root_entries|
      result = {}
      root_entries.sort_by { |entry| [MODE_PRIORITY.fetch(entry.fetch("strategy_mode")), entry.fetch("owner_rank", 0), entry.fetch("owner_schema")] }.each do |root|
      root_schema = root.fetch("owner_schema")
      queue = [[root_schema, []]]
      seen = {root_schema => true}
      until queue.empty?
        schema, path = queue.shift
        candidate = result[schema]
        if candidate.nil? || ([MODE_PRIORITY.fetch(root.fetch("strategy_mode")), root.fetch("owner_rank", 0), path.length, root_schema, path_key(path)] <=>
                              [MODE_PRIORITY.fetch(candidate.fetch("strategy_mode")), candidate.fetch("owner_rank", 0), candidate.fetch("target_path").length, candidate.fetch("owner_schema"), path_key(candidate.fetch("target_path"))]) == -1
          result[schema] = root.merge("target_schema" => schema, "target_path" => path)
        end
        edges.fetch(schema, []).sort_by { |edge| [edge.fetch("to"), edge.fetch("field"), edge.fetch("container")] }.each do |edge|
          target = edge.fetch("to")
          next if seen.key?(target)

          seen[target] = true
          queue << [target, path + [edge.slice("field", "container")]]
        end
      end
      end
      result
    end
    owners = assign_owners.call(strategy_roots + handler_roots + rest_roots + response_roots)
    # A *List kind is the response envelope of its item type: kube-apiserver
    # never accepts a list on create/update, and every item is validated by
    # the item owner.  meta.ExtractList (apimachinery) is the executable path.
    by_schema.each do |schema, type|
      next if owners.key?(schema)

      items = type.fetch("field_definitions")["items"]
      item_schema = items.is_a?(Hash) && items["type"] == "array" ? items.dig("items", "reference") : nil
      next unless item_schema && owners.key?(item_schema)

      item_owner = owners.fetch(item_schema)
      if %w[rest_endpoint response].include?(item_owner.fetch("strategy_mode"))
        # The list envelope of a REST-endpoint kind is observed in the same
        # API differential operations as its items (list responses).
        owners[schema] = item_owner.merge("owner_schema" => schema, "owner_type" => schema, "target_schema" => schema, "target_path" => [])
        next
      end
      owners[schema] = item_owner.merge(
        "strategy_mode" => "list",
        "list_schema" => schema,
        "list_gvk" => type.fetch("gvks").first,
        "item_schema" => item_schema,
        "item_mode" => item_owner.fetch("strategy_mode"),
        "item_target_path" => item_owner.fetch("target_path"),
        "target_schema" => schema,
        "target_path" => []
      )
    end

    Array(types).sort_by { |type| type.fetch("schema") }.map do |type|
      schema = type.fetch("schema")
      owner = owners[schema]
      if owner
        mode = owner.fetch("strategy_mode")
        mapping = {
          "applicable" => true,
          "validation_mode" => mode,
          "owner_schema" => owner.fetch("owner_schema"),
          "owner_type" => owner.fetch("owner_type"),
          "owner_gvk" => owner.fetch("owner_gvk"),
          "target_path" => owner.fetch("target_path"),
          "strategy_import" => owner["strategy_import"],
          "strategy_pointer" => owner.fetch("strategy_pointer", false),
          "namespace_scoped" => owner.fetch("namespace_scoped", false),
          "constructor_arity" => owner.fetch("constructor_arity", 0),
          "constructor_arguments" => owner.fetch("constructor_arguments", []),
          "collaborators" => owner.fetch("collaborators", []),
          "strategy_source_path" => owner["strategy_source_path"],
          "internal_package" => owner["internal_package"],
          "internal_type" => owner["internal_type"],
          "version_import" => owner["version_import"],
          "external_package" => owner["external_package"],
          "external_type" => owner["internal_type"],
          "source_paths" => Array(owner["source_paths"] || [owner["strategy_source_path"], owner["internal_source_path"]]).compact.uniq,
          "constructor_safe" => owner.fetch("constructor_safe", true),
          "constructor_safety_reason" => owner["constructor_safety_reason"]
        }
        if %w[handler].include?(owner["item_mode"] || mode)
          mapping["handler_key"] = owner.fetch("handler_key")
          mapping["handler_call"] = owner.fetch("call")
          mapping["validation_import"] = owner.fetch("validation_import")
          mapping["metadata_policy"] = owner.fetch("metadata_policy")
          mapping["fixture"] = owner.fetch("fixture")
          mapping["expectations"] = owner.fetch("expectations")
        end
        mapping["evidence"] = owner["evidence"] if owner["evidence"]
        mapping["scheme_imports"] = owner["scheme_imports"] if owner["scheme_imports"]
        if %w[strategy constructor].include?(owner["item_mode"] || mode)
          strategy_fixture = strategy_fixture_for(owner)
          if strategy_fixture
            mapping["fixture"] = strategy_fixture.fetch("fixture", {})
            mapping["expectations"] = strategy_fixture["expectations"] if strategy_fixture["expectations"]
            nested = strategy_fixture.fetch("fixture", {}).fetch("nested", {})
            nested_entry = nested[schema] || nested[schema.split(".").last]
            mapping["expectations"] = nested_entry["expectations"] if nested_entry.is_a?(Hash) && nested_entry["expectations"]
          end
        end
        if mode == "list"
          mapping["list_schema"] = owner.fetch("list_schema")
          mapping["list_gvk"] = owner.fetch("list_gvk")
          mapping["item_schema"] = owner.fetch("item_schema")
          mapping["item_mode"] = owner.fetch("item_mode")
          mapping["item_target_path"] = owner.fetch("item_target_path")
        end
        mapping
      else
        external = external_mapping_for_schema(schema)
        source_paths = (external_source_paths(source_root, external) +
                        strategy_candidate_source_paths(schema, entries)).uniq.sort
        runtime_object_paths = runtime_object_source_paths(source_root, external)
        field_validator_paths = field_validator_source_paths(source_root, external)
        reason = if runtime_object_paths.empty?
                   "upstream concrete type does not implement runtime.Object; JSON decode is the only source-backed endpoint and is not validation"
                 elsif field_validator_paths.empty?
                   "upstream concrete type implements runtime.Object but no REST create/update strategy or registered field validator endpoint was found; JSON decode and Scheme observation are not validation"
                 else
                   "upstream source exposes field-validator code at #{field_validator_paths.join(', ')}, but no safe REST owner adapter is available for this descriptor; JSON decode alone is not validation"
                 end
        source_paths = (source_paths + runtime_object_paths + field_validator_paths).uniq.sort
        {
          "applicable" => false,
          "validation_mode" => "protocol",
          "owner_schema" => schema,
          "owner_type" => schema,
          "owner_gvk" => type.fetch("gvks").first,
          "target_path" => [],
          "external_package" => external.fetch("external_package"),
          "external_type" => external.fetch("external_type"),
          "source_paths" => source_paths,
          "validation_reason" => reason,
          "reason" => reason,
          "runtime_object_source_paths" => runtime_object_paths,
          "field_validator_source_paths" => field_validator_paths
        }
      end.merge("target_schema" => schema)
    end
  end

  MODE_PRIORITY = {"strategy" => 0, "constructor" => 0, "handler" => 1, "rest_endpoint" => 2, "response" => 3, "list" => 4}.freeze

  def strategy_inventory(source_root)
    with_hydrated_source(source_root) do |full_root|
      paths = Dir.glob(::File.join(full_root, "pkg/registry/**/strategy.go")) +
              Dir.glob(::File.join(full_root, "staging/src/k8s.io/**/pkg/registry/**/strategy.go"))
      paths.sort.filter_map do |path|
        content = ::File.read(path)
        # Some packages expose Strategy from a var block, while others expose
        # NewStrategy with collaborators.  Both are executable upstream
        # validation entrypoints and must remain in the owner inventory.
        standalone = content.match?(/(?:^|\n)\s*(?:var\s+)?Strategy\s*=/)
        constructor = content.match(/(?:^|\n)\s*func\s+NewStrategy\s*\(([^)]*)\)/)
        constructor_parameters = constructor ? parse_constructor_arguments(constructor[1]) : []
        constructor_arity = constructor_parameters.length
        constructor_safe, constructor_safety_reason, collaborators = constructor_safety(constructor_parameters, content)
        constructor_arguments = constructor_safe ? collaborators.map { |collaborator| collaborator.fetch("expression") } : []
        namespace_scoped = content.match?(/func\s*\([^)]*\)\s+NamespaceScoped\(\)\s+bool\s*\{\s*return\s+true/m)
        strategy_pointer = content.match?(/(?:^|\n)\s*(?:var\s+)?Strategy\s*=\s*&/)
        imports = parse_imports(content)
        match = nil
        content.scan(/func\s*\([^)]*\)\s+Validate\(ctx context\.Context,\s*obj runtime\.Object\) field\.ErrorList\s*\{/) do
          body = content[$~.end(0), 4000] || ""
          assertion = body.match(/\bobj\.\(\*(?:(\w+)\.)?([A-Za-z_][A-Za-z0-9_]*)\)/)
          next unless assertion

          alias_name, type_name = assertion.captures
          internal_package = imports[alias_name || ""]
          next unless internal_package&.match?(%r{\Ak8s\.io/(?:kubernetes|apiextensions-apiserver|kube-aggregator)/pkg/apis/})

          match = [internal_package, type_name]
          break
        end
        next unless match

        internal_package, internal_type = match
        relative = path.delete_prefix("#{full_root}/")
        strategy_import = if relative.start_with?("staging/src/")
                            relative.delete_prefix("staging/src/").delete_suffix("/strategy.go")
                          else
                            "k8s.io/kubernetes/#{relative.delete_suffix("/strategy.go")}" 
                          end
        version = preferred_version_for_strategy(internal_package, internal_type, full_root)
        versions = available_versions_for_strategy(internal_package, full_root)
        external_package = external_package_for_internal(internal_package, version)
        internal_version = internal_package_version(internal_package, version)
        next unless external_package && internal_version

        entry = {
          "strategy_import" => strategy_import,
          "standalone" => standalone,
          "strategy_mode" => if standalone
                               "strategy"
                             elsif constructor
                               "constructor"
                             else
                               "protocol"
                             end,
          "strategy_pointer" => strategy_pointer,
          "namespace_scoped" => namespace_scoped,
          "constructor_arity" => constructor_arity,
          "constructor_arguments" => constructor_arguments,
          "constructor_safe" => constructor_safe,
          "constructor_safety_reason" => constructor_safety_reason,
          "collaborators" => collaborators,
          "strategy_source_path" => relative,
          "internal_package" => internal_package,
          "internal_type" => internal_type,
          "internal_source_path" => source_path_for_import(internal_version),
          "schema_prefix" => schema_prefix_for_internal(internal_package),
          "version" => version,
          "version_imports" => versions.map { |candidate| internal_package_version(internal_package, candidate) },
          "version_import" => internal_version,
          "version_import_template" => "#{internal_package}/%{version}",
          "external_package" => external_package,
          "external_package_template" => external_package_for_internal(internal_package, "%{version}")
        }
        # events.k8s.io is served by the core Event strategy through its own
        # conversion package (pkg/apis/events/<version>): the same executable
        # validation owns the events.k8s.io descriptors.
        if internal_package == "k8s.io/kubernetes/pkg/apis/core" && internal_type == "Event"
          events_versions = available_versions_for_strategy("k8s.io/kubernetes/pkg/apis/events", full_root)
          events_entry = entry.merge(
            "schema_prefix" => "io.k8s.api.events",
            "version_imports" => events_versions.map { |candidate| "k8s.io/kubernetes/pkg/apis/events/#{candidate}" },
            "version_import_template" => "k8s.io/kubernetes/pkg/apis/events/%{version}",
            "external_package_template" => "k8s.io/api/events/%{version}",
            "version_import" => "k8s.io/kubernetes/pkg/apis/events/#{events_versions.last || "v1"}",
            "external_package" => "k8s.io/api/events/#{events_versions.last || "v1"}",
            # The events.k8s.io internal version is the core Event type
            # registered by pkg/apis/events; the decoder needs that group.
            "scheme_imports" => ["k8s.io/kubernetes/pkg/apis/events"]
          )
          [entry, events_entry]
        else
          entry
        end
      end.flatten.uniq { |entry| [entry.fetch("strategy_import"), entry.fetch("schema_prefix")] }
    end
  end

  def normalize_requests(requests)
    seen = {}
    Array(requests).map do |request|
      entry = request.transform_keys(&:to_s)
      id = String(entry.fetch("id"))
      raise OracleError, "duplicate Kubernetes validation oracle request #{id.inspect}" if seen.key?(id)

      mapping = entry["validation_mapping"]
      unless mapping.nil? || mapping.is_a?(Hash)
        raise OracleError, "validation mapping for #{id.inspect} must be an object"
      end
      if mapping && mapping["applicable"] == false
        mapping = nil
      elsif mapping && mapping["validation_mode"] == "protocol"
        raise OracleError, "protocol validation mapping for #{id.inspect} is decode-only and cannot be applicable"
      elsif mapping && !VALIDATION_MODES.include?(mapping["validation_mode"].to_s)
        raise OracleError, "validation mapping for #{id.inspect} has an unknown mode #{mapping["validation_mode"].inspect}"
      elsif mapping && mapping["validation_mode"] == "constructor" && mapping["constructor_safe"] != true
        raise OracleError, "constructor validation mapping for #{id.inspect} is not source-backed safe"
      elsif mapping && %w[rest_endpoint response].include?(mapping["validation_mode"]) &&
            !(mapping["evidence"].is_a?(Hash) && Array(mapping.dig("evidence", "operations")).any?)
        raise OracleError, "#{mapping["validation_mode"]} validation mapping for #{id.inspect} must reference API differential operations"
      end
      evidence_only = mapping && %w[rest_endpoint response].include?(mapping["validation_mode"])
      validation_reason = entry.fetch("validation_reason", "")
      unless validation_reason.is_a?(String)
        raise OracleError, "validation reason for #{id.inspect} must be a string"
      end
      validation_source_paths = entry.fetch("validation_source_paths", mapping ? mapping["source_paths"] : [])
      unless validation_source_paths.is_a?(Array) && !validation_source_paths.empty? &&
             validation_source_paths.all? { |path| path.is_a?(String) && !path.empty? }
        raise OracleError, "validation source paths for #{id.inspect} must be an array of paths"
      end
      %w[fixture_json invalid_fixture_json missing_fixture_json update_fixture_json].each do |key|
        value = entry.fetch(key)
        parsed = JSON.parse(value, create_additions: false, max_nesting: 256)
        if mapping && !evidence_only && (!parsed.is_a?(Hash) || parsed.empty?)
          raise OracleError, "validation oracle request #{id.inspect} #{key} must be a non-empty object fixture"
        end
        # A handler root's "missing" fixture is the empty request body the REST
        # handler itself receives; every other fixture must carry a field.
        empty_body_allowed = mapping && mapping["validation_mode"] == "handler" && key == "missing_fixture_json"
        if mapping && !evidence_only && !empty_body_allowed && parsed.is_a?(Hash) && (parsed.keys.map(&:to_s) - %w[apiVersion kind]).empty?
          raise OracleError, "validation oracle request #{id.inspect} #{key} must contain a meaningful resource field"
        end
      rescue JSON::ParserError => error
        raise OracleError, "validation oracle request #{id.inspect} #{key} is invalid JSON: #{error.message}"
      end
      if mapping && !evidence_only && entry.fetch("fixture_json") == entry.fetch("update_fixture_json")
        raise OracleError, "validation oracle request #{id.inspect} update fixture must be independent from the valid fixture"
      end
      expectations = normalize_expectations(entry.fetch("validation_expectations", {
        "create" => true,
        "invalid" => false,
        "missing" => false,
        "update" => true
      }), id)
      seen[id] = true
      {
        "id" => id,
        "validation_mapping" => mapping,
        "validation_reason" => validation_reason,
        "validation_source_paths" => validation_source_paths,
        "fixture_json" => entry.fetch("fixture_json"),
        "invalid_fixture_json" => entry.fetch("invalid_fixture_json"),
        "missing_fixture_json" => entry.fetch("missing_fixture_json"),
        "update_fixture_json" => entry.fetch("update_fixture_json"),
        "validation_expectations" => expectations
      }.freeze
    end.sort_by { |entry| entry.fetch("id") }.freeze
  end

  def normalize_expectations(value, id)
    unless value.is_a?(Hash)
      raise OracleError, "validation expectations for #{id.inspect} must be an object"
    end

    expected_keys = %w[create invalid missing update]
    unless value.keys.map(&:to_s).sort == expected_keys.sort
      raise OracleError, "validation expectations for #{id.inspect} must contain #{expected_keys.join(', ')}"
    end
    expected_keys.to_h do |key|
      expected = value.fetch(key) { value.fetch(key.to_sym) }
      unless expected == true || expected == false
        raise OracleError, "validation expectation #{id.inspect}/#{key} must be boolean"
      end

      [key, expected]
    end.freeze
  end

  def go_source(requests, mappings)
    executable = mappings.select { |mapping| %w[strategy constructor handler list].include?(mapping.fetch("validation_mode")) }
    strategy_mappings = executable.select { |mapping| %w[strategy constructor].include?(mapping.fetch("validation_mode")) || (mapping.fetch("validation_mode") == "list" && %w[strategy constructor].include?(mapping["item_mode"])) }
    handler_mappings = executable.select { |mapping| mapping.fetch("validation_mode") == "handler" || (mapping.fetch("validation_mode") == "list" && mapping["item_mode"] == "handler") }
    strategy_imports = strategy_mappings.map { |mapping| mapping.fetch("strategy_import") }.uniq.sort
    internal_groups = (executable.filter_map { |mapping| mapping["internal_package"] } +
                       executable.flat_map { |mapping| Array(mapping["scheme_imports"]) }).uniq.sort
    version_imports = executable.filter_map { |mapping| mapping["version_import"] }.uniq.sort
    handler_imports = handler_mappings.map { |mapping| mapping.fetch("validation_import") }.uniq.sort
    collaborators = strategy_mappings.flat_map { |mapping| Array(mapping["collaborators"]) }
    collaborator_imports = collaborators.filter_map { |collaborator| collaborator["import"] }.uniq.sort
    helpers = collaborators.filter_map { |collaborator| collaborator["helper"] }.uniq.sort
    helper_imports = ["k8s.io/apimachinery/pkg/api/meta"]
    helper_imports << "k8s.io/apimachinery/pkg/api/errors" << "k8s.io/kubernetes/pkg/apis/admissionregistration" if helpers.include?("policy_getter")
    # Only API packages register themselves on the scheme; apimachinery's
    # meta/v1 types are already registered by every group's AddToScheme.
    registrable = lambda { |path| path.match?(%r{\A(?:k8s\.io/kubernetes|k8s\.io/apiextensions-apiserver|k8s\.io/kube-aggregator)/pkg/apis/}) }
    imports = (strategy_imports + internal_groups + version_imports + handler_imports + collaborator_imports + helper_imports + [
      "k8s.io/apimachinery/pkg/runtime",
      "k8s.io/apimachinery/pkg/runtime/schema",
      "k8s.io/apimachinery/pkg/runtime/serializer",
      "k8s.io/apimachinery/pkg/util/validation/field",
      "k8s.io/apiserver/pkg/registry/rest",
      "k8s.io/apiserver/pkg/endpoints/request",
      "k8s.io/apiserver/pkg/authentication/user",
      "k8s.io/kubernetes/pkg/api/legacyscheme"
    ]).uniq.sort
    aliases = imports.each_with_index.to_h { |path, index| [path, "validationpkg#{index}"] }
    runtime_alias = aliases.fetch("k8s.io/apimachinery/pkg/runtime")
    schema_alias = aliases.fetch("k8s.io/apimachinery/pkg/runtime/schema")
    serializer_alias = aliases.fetch("k8s.io/apimachinery/pkg/runtime/serializer")
    field_alias = aliases.fetch("k8s.io/apimachinery/pkg/util/validation/field")
    rest_alias = aliases.fetch("k8s.io/apiserver/pkg/registry/rest")
    request_alias = aliases.fetch("k8s.io/apiserver/pkg/endpoints/request")
    user_alias = aliases.fetch("k8s.io/apiserver/pkg/authentication/user")
    legacyscheme_alias = aliases.fetch("k8s.io/kubernetes/pkg/api/legacyscheme")
    meta_alias = aliases["k8s.io/apimachinery/pkg/api/meta"]
    errors_alias = aliases["k8s.io/apimachinery/pkg/api/errors"]
    admission_internal_alias = aliases["k8s.io/kubernetes/pkg/apis/admissionregistration"]

    strategies = strategy_mappings.to_h { |mapping| [mapping.fetch("strategy_import"), mapping] }
    strategy_source = strategies.sort.map do |path, mapping|
      expression = case mapping.fetch("validation_mode") == "list" ? mapping.fetch("item_mode") : mapping.fetch("validation_mode")
                   when "constructor"
                     unless mapping.fetch("constructor_safe") == true
                       raise OracleError, "constructor #{path} is not source-backed safe"
                     end
                     arguments = Array(mapping["collaborators"]).map do |collaborator|
                       template = collaborator.fetch("expression")
                       alias_name = collaborator["import"] ? aliases.fetch(collaborator.fetch("import")) : nil
                       template.gsub("%{alias}", alias_name.to_s)
                     end.join(", ")
                     "#{aliases.fetch(path)}.NewStrategy(#{arguments})"
                   when "strategy"
                     mapping.fetch("strategy_pointer") ? "#{aliases.fetch(path)}.Strategy" : "&#{aliases.fetch(path)}.Strategy"
                   else
                     raise OracleError, "unsupported upstream validation mode for #{path}"
                   end
      "\tcase #{JSON.generate(path)}:\n\t\treturn #{expression}, nil"
    end.join("\n")
    handlers = handler_mappings.to_h { |mapping| [mapping.fetch("handler_key"), mapping] }
    handler_source = handlers.sort.map do |key, mapping|
      call = mapping.fetch("handler_call")
      call = call.gsub("%{validation}", aliases.fetch(mapping.fetch("validation_import")))
      call = call.gsub("%{internal}", mapping["internal_package"] ? aliases.fetch(mapping.fetch("internal_package")) : "")
      call = call.gsub("%{versioned}", aliases.fetch(mapping.fetch("version_import")))
      "\tcase #{JSON.generate(key)}:\n\t\treturn func(object #{runtime_alias}.Object) #{field_alias}.ErrorList { return #{call} }, nil"
    end.join("\n")
    mapping_by_id = requests.to_h { |request| [request.fetch("id"), request["validation_mapping"]] }
    gvk_literal = lambda do |gvk, internal|
      version = internal ? "#{runtime_alias}.APIVersionInternal" : JSON.generate(gvk.fetch("version"))
      "#{schema_alias}.GroupVersionKind{Group: #{JSON.generate(gvk.fetch("group"))}, Version: #{version}, Kind: #{JSON.generate(gvk.fetch("kind"))}}"
    end
    mapping_source = mapping_by_id.sort.map do |id, mapping|
      if mapping.nil?
        request = requests.find { |entry| entry.fetch("id") == id }
        <<~GO.chomp
          	case #{JSON.generate(id)}:
          		return validationMapping{mode: "na", reason: #{JSON.generate(request.fetch("validation_reason"))}, sourcePaths: []string{#{request.fetch("validation_source_paths").map { |path| JSON.generate(path) }.join(", ")}}}, nil
        GO
      elsif mapping.fetch("validation_mode") == "protocol"
        raise OracleError, "protocol validation mapping #{id.inspect} is decode-only and cannot be applicable"
      elsif %w[rest_endpoint response].include?(mapping.fetch("validation_mode"))
        operations = Array(mapping.dig("evidence", "operations")).map { |operation| JSON.generate(operation) }.join(", ")
        <<~GO.chomp
          	case #{JSON.generate(id)}:
          		return validationMapping{mode: #{JSON.generate(mapping.fetch("validation_mode"))}, evidenceReport: #{JSON.generate(mapping.dig("evidence", "report"))}, evidenceOperations: []string{#{operations}}, sourcePaths: []string{#{Array(mapping["source_paths"]).map { |path| JSON.generate(path) }.join(", ")}}}, nil
        GO
      else
        mode = mapping.fetch("validation_mode")
        item_mode = mode == "list" ? mapping.fetch("item_mode") : mode
        convert = !mapping["internal_package"].nil?
        internal_gvk = convert ? gvk_literal.call(mapping.fetch("owner_gvk"), true) : "#{schema_alias}.GroupVersionKind{}"
        list_gvk = mode == "list" ? gvk_literal.call(mapping.fetch("list_gvk"), false) : "#{schema_alias}.GroupVersionKind{}"
        <<~GO.chomp
          	case #{JSON.generate(id)}:
          		return validationMapping{
          			mode: #{JSON.generate(mode)},
          			itemMode: #{JSON.generate(item_mode)},
          			strategyKey: #{JSON.generate(mapping["strategy_import"].to_s)},
          			handlerKey: #{JSON.generate(mapping["handler_key"].to_s)},
          			convert: #{convert},
          			ownerGVK: #{gvk_literal.call(mapping.fetch("owner_gvk"), false)},
          			internalGVK: #{internal_gvk},
          			listGVK: #{list_gvk},
          			resource: #{JSON.generate(mapping["owner_resource"].to_s)},
          		}, nil
        GO
      end
    end.join("\n")
    register_internal = internal_groups.select(&registrable).map { |path| "\tif err := #{aliases.fetch(path)}.AddToScheme(scheme); err != nil { return nil, fmt.Errorf(\"register internal #{path}: %w\", err) }" }.join("\n")
    register_versions = version_imports.select(&registrable).map { |path| "\tif err := #{aliases.fetch(path)}.AddToScheme(scheme); err != nil { return nil, fmt.Errorf(\"register version #{path}: %w\", err) }" }.join("\n")
    import_source = imports.map { |path| "\t#{aliases.fetch(path)} #{JSON.generate(path)}" }.join("\n")
    helper_source = +""
    if helpers.include?("resource_resolver")
      helper_source << <<~GO
        // builtinResourceResolver maps a registered kind to its plural resource the
        // way NewDiscoveryResourceResolver observes it for built-in types.
        func builtinResourceResolver(gvk #{schema_alias}.GroupVersionKind) (#{schema_alias}.GroupVersionResource, error) {
          if !#{legacyscheme_alias}.Scheme.Recognizes(gvk) {
            return #{schema_alias}.GroupVersionResource{}, fmt.Errorf("unrecognized kind %s", gvk.String())
          }
          plural, _ := #{meta_alias}.UnsafeGuessKindToResource(gvk)
          return plural, nil
        }
      GO
    end
    if helpers.include?("policy_getter")
      helper_source << <<~GO
        // fixturePolicyGetter reports every policy as absent; binding fixtures carry no
        // paramRef, so the strategies never reach it.
        type fixturePolicyGetter struct{}

        func (fixturePolicyGetter) GetValidatingAdmissionPolicy(ctx context.Context, name string) (*#{admission_internal_alias}.ValidatingAdmissionPolicy, error) {
          return nil, #{errors_alias}.NewNotFound(#{schema_alias}.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"}, name)
        }

        func (fixturePolicyGetter) GetMutatingAdmissionPolicy(ctx context.Context, name string) (*#{admission_internal_alias}.MutatingAdmissionPolicy, error) {
          return nil, #{errors_alias}.NewNotFound(#{schema_alias}.GroupResource{Group: "admissionregistration.k8s.io", Resource: "mutatingadmissionpolicies"}, name)
        }
      GO
    end
    list_support = "true"

    source = <<~GO
      package main

      import (
      #{import_source}
        "context"
        "encoding/json"
        "fmt"
        "os"
        "runtime"
      )

      type request struct {
        ID string `json:"id"`
        ValidationMapping map[string]interface{} `json:"validation_mapping"`
        ValidationReason string `json:"validation_reason"`
        ValidationSourcePaths []string `json:"validation_source_paths"`
        FixtureJSON string `json:"fixture_json"`
        InvalidFixtureJSON string `json:"invalid_fixture_json"`
        MissingFixtureJSON string `json:"missing_fixture_json"`
        UpdateFixtureJSON string `json:"update_fixture_json"`
        ValidationExpectations map[string]bool `json:"validation_expectations"`
      }

      type errorResult struct {
        Type string `json:"type"`
        Field string `json:"field"`
        Detail string `json:"detail"`
        Error string `json:"error"`
      }

      type operationResult struct {
        Completed bool `json:"completed"`
        Accepted bool `json:"accepted"`
        Errors []errorResult `json:"errors"`
        Error string `json:"error,omitempty"`
        ExpectedAccepted bool `json:"expected_accepted"`
        ExpectationMatches bool `json:"expectation_matches"`
      }

      type result struct {
        ID string `json:"id"`
        Passed bool `json:"passed"`
        Applicable bool `json:"applicable"`
        Mode string `json:"mode,omitempty"`
        Evidence map[string]interface{} `json:"evidence,omitempty"`
        Reason string `json:"reason,omitempty"`
        OwnerSchema string `json:"owner_schema,omitempty"`
        TargetPath []map[string]string `json:"target_path,omitempty"`
        SourcePaths []string `json:"source_paths,omitempty"`
        Create operationResult `json:"create"`
        Invalid operationResult `json:"invalid"`
        Update operationResult `json:"update"`
        Missing operationResult `json:"missing"`
        Error string `json:"error,omitempty"`
      }

      type validationMapping struct {
        mode string
        itemMode string
        strategyKey string
        handlerKey string
        convert bool
        ownerGVK #{schema_alias}.GroupVersionKind
        internalGVK #{schema_alias}.GroupVersionKind
        resource string
        listGVK #{schema_alias}.GroupVersionKind
        externalKey string
        reason string
        sourcePaths []string
        evidenceReport string
        evidenceOperations []string
      }

      type validateFunc func(object #{runtime_alias}.Object) #{field_alias}.ErrorList

      #{helper_source}
      func strategyFor(key string) (#{rest_alias}.RESTCreateUpdateStrategy, error) {
        switch key {
      #{strategy_source}
        default:
          return nil, fmt.Errorf("unmapped strategy %q", key)
        }
      }

      func handlerFor(key string) (validateFunc, error) {
        switch key {
      #{handler_source}
        default:
          return nil, fmt.Errorf("unmapped handler %q", key)
        }
      }

      func mappingFor(id string) (validationMapping, error) {
        switch id {
      #{mapping_source}
        default:
          return validationMapping{}, fmt.Errorf("no validation mapping for %q", id)
        }
      }

      func registerScheme() (*#{runtime_alias}.Scheme, error) {
        scheme := #{legacyscheme_alias}.Scheme
      #{register_internal}
      #{register_versions}
        return scheme, nil
      }

      func errorsFor(items #{field_alias}.ErrorList) []errorResult {
        result := make([]errorResult, 0, len(items))
        for _, item := range items {
          result = append(result, errorResult{Type: item.Type.String(), Field: item.Field, Detail: item.Detail, Error: item.Error()})
        }
        return result
      }

      // decodeVersioned decodes the wire form without version conversion or
      // defaulting; it serves types that have no internal version.
      func decodeVersioned(deserializer #{runtime_alias}.Decoder, raw string, gvk #{schema_alias}.GroupVersionKind) (#{runtime_alias}.Object, error) {
        decoded, _, err := deserializer.Decode([]byte(raw), &gvk, nil)
        if err != nil { return nil, err }
        return decoded, nil
      }

      // decodeInternal decodes through the universal decoder the way the
      // apiserver request path does: versioned defaults are applied and the
      // object is converted to the internal version the strategy validates.
      func decodeInternal(scheme *#{runtime_alias}.Scheme, decoder #{runtime_alias}.Decoder, deserializer #{runtime_alias}.Decoder, raw string, mapping validationMapping) (#{runtime_alias}.Object, error) {
        if !mapping.convert {
          return decodeVersioned(deserializer, raw, mapping.ownerGVK)
        }
        decoded, _, err := decoder.Decode([]byte(raw), &mapping.ownerGVK, nil)
        if err != nil { return nil, err }
        target, err := scheme.New(mapping.internalGVK)
        if err != nil { return nil, err }
        if err := scheme.Convert(decoded, target, nil); err != nil { return nil, err }
        object, ok := target.(#{runtime_alias}.Object)
        if !ok { return nil, fmt.Errorf("converted %T is not runtime.Object", target) }
        return object, nil
      }

      // decodeItems decodes a list envelope with defaulting and conversion and
      // returns the items; kube-apiserver validates each item, never the envelope.
      func decodeItems(scheme *#{runtime_alias}.Scheme, decoder #{runtime_alias}.Decoder, deserializer #{runtime_alias}.Decoder, raw string, mapping validationMapping) ([]#{runtime_alias}.Object, error) {
        var decoded #{runtime_alias}.Object
        var err error
        if mapping.convert {
          decoded, _, err = decoder.Decode([]byte(raw), &mapping.listGVK, nil)
        } else {
          decoded, err = decodeVersioned(deserializer, raw, mapping.listGVK)
        }
        if err != nil { return nil, err }
        items, err := #{meta_alias}.ExtractList(decoded)
        if err != nil { return nil, fmt.Errorf("extract list items: %w", err) }
        return items, nil
      }

      func runValidation(mapping validationMapping, object #{runtime_alias}.Object, old #{runtime_alias}.Object, update bool) (result operationResult) {
        // A named result keeps the recovered panic visible to the caller.
        result = operationResult{Errors: []errorResult{}, Completed: false}
        defer func() {
          if recovered := recover(); recovered != nil {
            result.Error = fmt.Sprintf("panic: %v", recovered)
            result.Accepted = false
            result.Completed = true
          }
        }()
        // kube-apiserver always runs strategies under a request context that
        // carries the RequestInfo of the served group/version (and the request
        // namespace); several strategies read it (Event, PodGroup).
        ctx := context.Background()
        verb := "create"
        if update { verb = "update" }
        namespace := ""
        if accessor, err := #{meta_alias}.Accessor(object); err == nil { namespace = accessor.GetNamespace() }
        ctx = #{request_alias}.WithRequestInfo(ctx, &#{request_alias}.RequestInfo{
          IsResourceRequest: true,
          Verb: verb,
          APIGroup: mapping.ownerGVK.Group,
          APIVersion: mapping.ownerGVK.Version,
          Resource: mapping.resource,
          Namespace: namespace,
          Name: func() string { if accessor, err := #{meta_alias}.Accessor(object); err == nil { return accessor.GetName() }; return "" }(),
        })
        if namespace != "" { ctx = #{request_alias}.WithNamespace(ctx, namespace) }
        // The API differential requester is the system:masters identity that
        // kube-apiserver authenticates before any strategy runs.
        ctx = #{request_alias}.WithUser(ctx, &#{user_alias}.DefaultInfo{Name: "m1-oracle", UID: "1", Groups: []string{"system:masters", "system:authenticated"}})
        switch mapping.itemMode {
        case "strategy", "constructor":
          strategy, err := strategyFor(mapping.strategyKey)
          if err != nil { result.Error = err.Error(); result.Completed = true; return result }
          if update {
            strategy.PrepareForUpdate(ctx, object, old)
            result.Errors = errorsFor(strategy.ValidateUpdate(ctx, object, old))
          } else {
            strategy.PrepareForCreate(ctx, object)
            result.Errors = errorsFor(strategy.Validate(ctx, object))
          }
        case "handler":
          handler, err := handlerFor(mapping.handlerKey)
          if err != nil { result.Error = err.Error(); result.Completed = true; return result }
          result.Errors = errorsFor(handler(object))
        default:
          result.Error = fmt.Sprintf("unsupported item mode %q", mapping.itemMode)
          result.Completed = true
          return result
        }
        result.Accepted = len(result.Errors) == 0 && result.Error == ""
        result.Completed = true
        return result
      }

      func runOperation(mapping validationMapping, scheme *#{runtime_alias}.Scheme, decoder #{runtime_alias}.Decoder, deserializer #{runtime_alias}.Decoder, raw string, oldRaw string, update bool) (operationResult) {
        if mapping.mode == "list" {
          items, err := decodeItems(scheme, decoder, deserializer, raw, mapping)
          if err != nil { return operationResult{Errors: []errorResult{}, Error: fmt.Sprintf("decode list fixture: %v", err), Completed: true} }
          var olds []#{runtime_alias}.Object
          if update {
            olds, err = decodeItems(scheme, decoder, deserializer, oldRaw, mapping)
            if err != nil { return operationResult{Errors: []errorResult{}, Error: fmt.Sprintf("decode old list fixture: %v", err), Completed: true} }
          }
          aggregate := operationResult{Errors: []errorResult{}, Completed: true, Accepted: true}
          if len(items) == 0 {
            aggregate.Accepted = false
            aggregate.Errors = append(aggregate.Errors, errorResult{Type: "FieldValueRequired", Field: "items", Detail: "", Error: "items: Required value"})
          }
          for index, item := range items {
            var old #{runtime_alias}.Object
            if update && index < len(olds) { old = olds[index] }
            partial := runValidation(mapping, item, old, update)
            if partial.Error != "" { aggregate.Error = partial.Error; aggregate.Accepted = false; return aggregate }
            for _, item := range partial.Errors {
              item.Field = fmt.Sprintf("items[%d].%s", index, item.Field)
              aggregate.Errors = append(aggregate.Errors, item)
            }
          }
          aggregate.Accepted = len(aggregate.Errors) == 0 && aggregate.Error == ""
          return aggregate
        }
        object, err := decodeInternal(scheme, decoder, deserializer, raw, mapping)
        if err != nil { return operationResult{Errors: []errorResult{}, Error: fmt.Sprintf("decode fixture: %v", err), Completed: true} }
        var old #{runtime_alias}.Object
        if update {
          old, err = decodeInternal(scheme, decoder, deserializer, oldRaw, mapping)
          if err != nil { return operationResult{Errors: []errorResult{}, Error: fmt.Sprintf("decode old fixture: %v", err), Completed: true} }
        }
        return runValidation(mapping, object, old, update)
      }

      func bindExpectation(result operationResult, expected bool) operationResult {
        result.ExpectedAccepted = expected
        result.ExpectationMatches = result.Completed && result.Accepted == expected &&
          ((expected && len(result.Errors) == 0 && result.Error == "") ||
           (!expected && len(result.Errors) > 0 && result.Error == ""))
        return result
      }

      func compareOne(input request, scheme *#{runtime_alias}.Scheme, decoder #{runtime_alias}.Decoder, deserializer #{runtime_alias}.Decoder) (result result) {
        result.ID = input.ID
        mapping, err := mappingFor(input.ID)
        if err != nil {
          result.Error = err.Error()
          return
        }
        result.Mode = mapping.mode
        if mapping.mode == "na" {
          result.Applicable = false
          result.Reason = mapping.reason
          result.SourcePaths = mapping.sourcePaths
          result.Passed = true
          return
        }
        if mapping.mode == "rest_endpoint" || mapping.mode == "response" {
          result.Applicable = true
          result.SourcePaths = mapping.sourcePaths
          result.Evidence = map[string]interface{}{"report": mapping.evidenceReport, "operations": mapping.evidenceOperations}
          result.Passed = len(mapping.evidenceOperations) > 0
          return
        }
        result.Applicable = true
        result.OwnerSchema = mapping.ownerGVK.String()
        if mapping.itemMode == "handler" {
          result.SourcePaths = []string{mapping.handlerKey}
        } else {
          result.SourcePaths = []string{mapping.strategyKey}
        }
        result.Create = bindExpectation(runOperation(mapping, scheme, decoder, deserializer, input.FixtureJSON, "", false), input.ValidationExpectations["create"])
        result.Invalid = bindExpectation(runOperation(mapping, scheme, decoder, deserializer, input.InvalidFixtureJSON, "", false), input.ValidationExpectations["invalid"])
        result.Update = bindExpectation(runOperation(mapping, scheme, decoder, deserializer, input.UpdateFixtureJSON, input.FixtureJSON, true), input.ValidationExpectations["update"])
        result.Missing = bindExpectation(runOperation(mapping, scheme, decoder, deserializer, input.MissingFixtureJSON, "", false), input.ValidationExpectations["missing"])
        result.Passed = result.Error == "" && result.Create.ExpectationMatches && result.Invalid.ExpectationMatches && result.Update.ExpectationMatches && result.Missing.ExpectationMatches
        return
      }

      func main() {
        var input []request
        if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }
        scheme, err := registerScheme()
        if err != nil { fmt.Fprintln(os.Stderr, "scheme:", err); os.Exit(3) }
        codecs := #{serializer_alias}.NewCodecFactory(scheme)
        decoder := codecs.UniversalDecoder()
        deserializer := codecs.UniversalDeserializer()
        results := make([]result, 0, len(input))
        for _, item := range input {
          func() {
            defer func() { if recovered := recover(); recovered != nil { results = append(results, result{ID: item.ID, Error: fmt.Sprintf("panic: %v", recovered)}) } }()
            _, mappingErr := mappingFor(item.ID)
            if mappingErr != nil {
              results = append(results, result{ID: item.ID, Applicable: true, Passed: false, Error: mappingErr.Error()})
              return
            }
            results = append(results, compareOne(item, scheme, decoder, deserializer))
          }()
        }
        if err := json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"go_version": runtime.Version(), "results": results}); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(4) }
      }
    GO
    [source, mappings.sort_by { |mapping| mapping.fetch("target_schema") }.uniq]
  end

  def schema_edges(by_schema)
    by_schema.to_h do |schema, type|
      edges = []
      type.fetch("field_definitions").each do |field, definition|
        edge = reference_edge(field, definition)
        edges << edge if edge && by_schema.key?(edge.fetch("to"))
      end
      [schema, edges]
    end
  end

  def reference_edge(field, definition)
    if definition["type"] == "array" && definition.dig("items", "reference")
      {"field" => field, "container" => "array", "to" => definition.dig("items", "reference")}
    elsif definition["type"] == "object" && definition.dig("additional_properties", "reference")
      {"field" => field, "container" => "map", "to" => definition.dig("additional_properties", "reference")}
    elsif definition["reference"]
      {"field" => field, "container" => "object", "to" => definition["reference"]}
    elsif definition["schema_reference"]
      {"field" => field, "container" => "scalar", "to" => definition["schema_reference"]}
    end
  end

  def parse_constructor_arguments(arguments)
    text = arguments.to_s.strip
    return [] if text.empty?

    # Kubernetes constructors use ordinary Go parameters for the strategy
    # collaborators in the pinned source.  Keep the parser deliberately
    # conservative: grouped names and variadic parameters are not safe to
    # synthesize without a typed value.
    parts = text.split(",").map(&:strip)
    return [] if parts.any?(&:empty?)

    parts.map do |part|
      match = part.match(/\A([A-Za-z_]\w*)\s+(.+?)\z/)
      match ? match.captures : [part, ""]
    end
  end

  def constructor_safety(arguments, _content)
    return [true, "NewStrategy has no collaborators", []] if arguments.empty?

    collaborators = arguments.map do |(name, type)|
      spec = COLLABORATORS.find { |candidate| candidate.fetch("pattern").match?(type.to_s) }
      unless spec
        return [false, "constructor collaborator #{name} #{type} has no source-backed implementation in the pinned checkout", []]
      end

      spec.reject { |key, _value| key == "pattern" }.merge("name" => name.to_s, "type" => type.to_s)
    end
    reason = "constructor collaborators are source-backed: " +
             collaborators.map { |collaborator| "#{collaborator["name"]} #{collaborator["type"]} => #{collaborator["expression"]}" }.join(", ")
    [true, reason, collaborators]
  rescue StandardError => error
    [false, "constructor safety analysis failed closed: #{error.message}", []]
  end

  def external_source_paths(source_root, external)
    package_root = ::File.join(source_root, "staging/src", external.fetch("external_package"))
    type = external.fetch("external_type")
    paths = Dir.glob(::File.join(package_root, "**/*.go")).sort.filter_map do |path|
      content = ::File.read(path)
      next unless content.match?(/(?:^|\n)\s*type\s+#{Regexp.escape(type)}\b/m)

      path.delete_prefix("#{source_root}/")
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end
    paths.empty? ? [external.fetch("source_path")] : paths
  end

  def strategy_candidate_source_paths(schema, entries)
    entries.filter_map do |entry|
      next unless entry.fetch("schema_prefix").to_s != "" &&
                  schema.start_with?("#{entry.fetch("schema_prefix") }.") &&
                  schema.end_with?(".#{entry.fetch("internal_type")}")

      entry.fetch("strategy_source_path")
    end
  end

  def runtime_object_source_paths(source_root, external)
    package_root = ::File.join(source_root, "staging/src", external.fetch("external_package"))
    type = external.fetch("external_type")
    Dir.glob(::File.join(package_root, "**/*.go")).sort.filter_map do |path|
      content = ::File.read(path)
      next unless content.match?(/func\s*\([^)]*\*?#{Regexp.escape(type)}\)?\s+(?:GetObjectKind|DeepCopyObject)\s*\(/)

      path.delete_prefix("#{source_root}/")
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end
  end

  def field_validator_source_paths(source_root, external)
    # Manual validators live under pkg/apis/<group>/validation in the
    # Kubernetes source tree.  This is evidence only; unless a strategy owner
    # is also available, the endpoint is not executable by this probe.
    package = external.fetch("external_package")
    match = package.match(%r{\Ak8s\.io/api/([^/]+)/[^/]+\z})
    return [] unless match

    group = match[1]
    type = external.fetch("external_type")
    root = ::File.join(source_root, "pkg/apis", group, "validation")
    Dir.glob(::File.join(root, "**/*.go")).sort.filter_map do |path|
      content = ::File.read(path)
      next unless content.match?(/func\s+Validate[A-Za-z0-9_]*\s*\([^)]*\*[^)]*\b#{Regexp.escape(type)}\b/m)

      path.delete_prefix("#{source_root}/")
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end
  end

  def parse_imports(content)
    imports = {}
    content.scan(/import\s*\((.*?)\)/m).each do |match|
      match.first.scan(/^\s*(?:(\w+)\s+)?"([^"]+)"/).each do |alias_name, path|
        imports[alias_name || path.split("/").last] = path
      end
    end
    content.scan(/import\s+(?:(\w+)\s+)?"([^"]+)"/).each do |alias_name, path|
      imports[alias_name || path.split("/").last] = path
    end
    imports
  end

  def schema_prefix_for_internal(internal_package)
    case internal_package
    when %r{\Ak8s\.io/kubernetes/pkg/apis/([^/]+)\z}
      "io.k8s.api.#{$1}"
    when %r{\Ak8s\.io/(apiextensions-apiserver|kube-aggregator)/pkg/apis/([^/]+)\z}
      "io.k8s.#{$1}.pkg.apis.#{$2}"
    end
  end

  def external_package_for_internal(internal_package, version)
    case internal_package
    when %r{\Ak8s\.io/kubernetes/pkg/apis/([^/]+)\z}
      group = Regexp.last_match(1)
      group == "core" ? "k8s.io/api/core/#{version}" : "k8s.io/api/#{group}/#{version}"
    when %r{\Ak8s\.io/(apiextensions-apiserver|kube-aggregator)/pkg/apis/([^/]+)\z}
      "k8s.io/#{Regexp.last_match(1)}/pkg/apis/#{Regexp.last_match(2)}/#{version}"
    end
  end

  def internal_package_version(internal_package, version)
    return unless internal_package

    "#{internal_package}/#{version}"
  end

  def preferred_version_for_strategy(internal_package, _internal_type, source_root)
    relative = if internal_package.start_with?("k8s.io/kubernetes/")
                 internal_package.delete_prefix("k8s.io/kubernetes/")
               else
                 "staging/src/#{internal_package}"
               end
    candidates = Dir.glob(::File.join(source_root, relative, "v*"))
    versions = candidates.filter_map { |path| ::File.basename(path) if ::File.directory?(path) && ::File.basename(path).match?(/\Av\d/) }
    versions.max_by { |version| version_sort_key(version) } || "v1"
  end

  def available_versions_for_strategy(internal_package, source_root)
    relative = if internal_package.start_with?("k8s.io/kubernetes/")
                 internal_package.delete_prefix("k8s.io/kubernetes/")
               else
                 "staging/src/#{internal_package}"
               end
    versions = Dir.glob(::File.join(source_root, relative, "v*"))
      .filter_map { |path| ::File.basename(path) if ::File.directory?(path) && ::File.basename(path).match?(%r{\Av\d}) }
    versions.sort_by { |version| version_sort_key(version) }
  end

  def preferred_gvk(type)
    type.fetch("gvks").select { |gvk| !%w[DeleteOptions WatchEvent Status].include?(gvk.fetch("kind")) }.sort_by do |gvk|
      [version_sort_key(gvk.fetch("version")), gvk.fetch("group"), gvk.fetch("kind")]
    end.first
  end

  def version_sort_key(version)
    match = version.to_s.match(/\Av(\d+)(?:(alpha|beta)(\d+))?\z/)
    return [0, 0, 0] unless match

    stability = match[2].nil? ? 3 : (match[2] == "beta" ? 2 : 1)
    [Integer(match[1]), stability, Integer(match[3] || 0)]
  end

  def schema_source_path(schema)
    if schema.start_with?("io.k8s.api.")
      "staging/src/k8s.io/api"
    elsif schema.start_with?("io.k8s.apiextensions-apiserver.")
      "staging/src/k8s.io/apiextensions-apiserver"
    elsif schema.start_with?("io.k8s.kube-aggregator.")
      "staging/src/k8s.io/kube-aggregator"
    else
      "pkg/apis"
    end
  end

  def external_mapping_for_schema(schema)
    parts = schema.split(".")
    if schema.start_with?("io.k8s.api.")
      group, version, type = parts.fetch(3), parts.fetch(4), parts.fetch(5)
      package = "k8s.io/api/#{group}/#{version}"
    elsif schema.start_with?("io.k8s.apimachinery.pkg.")
      relative = parts.drop(4)
      type = relative.pop
      package = "k8s.io/apimachinery/pkg/#{relative.join("/")}"
    elsif schema.start_with?("io.k8s.apiextensions-apiserver.pkg.")
      relative = parts.drop(3)
      type = relative.pop
      package = "k8s.io/apiextensions-apiserver/#{relative.join("/")}"
    elsif schema.start_with?("io.k8s.kube-aggregator.pkg.")
      relative = parts.drop(3)
      type = relative.pop
      package = "k8s.io/kube-aggregator/#{relative.join("/")}"
    else
      raise OracleError, "cannot derive an upstream Go package for #{schema}"
    end
    {
      "external_package" => package,
      "external_type" => type,
      "source_path" => "staging/src/#{package}"
    }
  end

  def path_key(path)
    Array(path).map { |edge| "#{edge.fetch("field")}:#{edge.fetch("container")}" }.join("/")
  end

  def source_path_for_import(import_path)
    if import_path.start_with?("k8s.io/kubernetes/")
      import_path.delete_prefix("k8s.io/kubernetes/")
    else
      "staging/src/#{import_path}"
    end
  end

  def verify_source!(source_root)
    unless ::File.directory?(::File.join(source_root, ".git"))
      raise OracleError, "Kubernetes oracle source is not a Git checkout: #{source_root}"
    end
    commit = capture!("git", "-C", source_root, "rev-parse", "HEAD").strip
    raise OracleError, "Kubernetes oracle source commit must be #{SOURCE_COMMIT}, got #{commit}" unless commit == SOURCE_COMMIT
    tag = capture!("git", "-C", source_root, "describe", "--tags", "--exact-match", "HEAD").strip
    raise OracleError, "Kubernetes oracle source tag must be #{KUBERNETES_VERSION}, got #{tag.inspect}" unless tag == KUBERNETES_VERSION
    dirty = capture!("git", "-C", source_root, "status", "--porcelain", "--untracked-files=no").strip
    raise OracleError, "Kubernetes oracle source checkout has tracked modifications" unless dirty.empty?
  end

  def with_hydrated_source(source_root)
    Dir.mktmpdir("rubernetes-kubernetes-validation-source-") do |directory|
      _git_in, git_out, git_err, git_wait = Open3.popen3("git", "-C", source_root, "archive", "HEAD", "go.mod", "go.sum", "staging", "pkg", "plugin", "test")
      tar_in, _tar_out, tar_err, tar_wait = Open3.popen3("tar", "-x", "-C", directory)
      begin
        IO.copy_stream(git_out, tar_in)
      ensure
        tar_in.close unless tar_in.closed?
        git_out.close unless git_out.closed?
      end
      git_error = git_err.read
      tar_error = tar_err.read
      git_status = git_wait.value
      tar_status = tar_wait.value
      unless git_status.success? && tar_status.success?
        raise OracleError, "cannot hydrate pinned Kubernetes source: git=#{git_error.strip} tar=#{tar_error.strip}"
      end
      yield directory
    end
  rescue SystemCallError => error
    raise OracleError, "cannot hydrate pinned Kubernetes source: #{error.message}"
  end

  def execute_go(go:, source_root:, source:, requests:)
    with_hydrated_source(source_root) do |full_root|
      Dir.mktmpdir("rubernetes-kubernetes-validation-runner-") do |directory|
        ::File.write(::File.join(directory, "main.go"), source)
        ::File.write(::File.join(directory, "go.mod"), go_mod(full_root))
        _tidy_stdout, tidy_stderr, tidy_status = Open3.capture3(
          {"GOWORK" => "off", "CGO_ENABLED" => "0"}, go, "mod", "tidy", chdir: directory
        )
        unless tidy_status.success?
          detail = tidy_stderr.lines.last(30).join.strip
          raise OracleError, "Kubernetes validation oracle dependency resolution failed (#{tidy_status.exitstatus}): #{detail}"
        end
        stdout, stderr, status = Open3.capture3(
          {"GOWORK" => "off", "CGO_ENABLED" => "0"}, go, "run", ".",
          stdin_data: JSON.generate(requests), chdir: directory
        )
        unless status.success?
          detail = stderr.lines.last(40).join.strip
          raise OracleError, "Kubernetes validation oracle Go helper failed (#{status.exitstatus}): #{detail}"
        end
        document = JSON.parse(stdout, create_additions: false, max_nesting: 256)
        results = document.fetch("results")
        raise OracleError, "Kubernetes validation oracle results must be an array" unless results.is_a?(Array)
        [results, String(document.fetch("go_version"))]
      end
    end
  rescue JSON::ParserError => error
    raise OracleError, "Kubernetes validation oracle returned invalid JSON: #{error.message}"
  end

  def go_mod(source_root)
    replacements = ::File.read(::File.join(source_root, "go.mod")).lines.filter_map do |line|
      match = line.match(/^\s*(k8s\.io\/[^\s]+)\s*=>\s*(\.\/staging\/src\/[^\s]+)\s*$/)
      next unless match

      "#{match[1]} => #{::File.join(source_root, match[2].delete_prefix("./"))}"
    end
    <<~MOD
      module rubernetes.dev/m1-validation-oracle

      go 1.26.0

      require #{KUBERNETES_MODULE} v0.0.0

      replace (
      #{KUBERNETES_MODULE} => #{source_root}
      #{replacements.join("\n")}
      )
    MOD
  end

  def capture!(*argv)
    stdout, stderr, status = Open3.capture3(*argv)
    return stdout if status.success?

    raise OracleError, "command failed: #{argv.join(" ")}: #{stderr.strip}"
  rescue SystemCallError => error
    raise OracleError, "command could not execute: #{argv.first}: #{error.message}"
  end
end
