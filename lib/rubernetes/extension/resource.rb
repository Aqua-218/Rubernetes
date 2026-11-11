# frozen_string_literal: true

module Rubernetes
  module Extension
    GROUP = "rubernetes.io"
    VERSION = "v1alpha1"
    KIND = "Extension"
    RESOURCE = "extensions"
    API_VERSION = "#{GROUP}/#{VERSION}".freeze
    PATH = "/apis/#{GROUP}/#{VERSION}/#{RESOURCE}".freeze
    CRD_NAME = "#{RESOURCE}.#{GROUP}".freeze
    MAX_SOURCE_BYTES = 262_144

    component_status = {
      "type" => "object",
      "properties" => {
        "loaded" => {"type" => "boolean"}, "observedGeneration" => {"type" => "integer", "format" => "int64"},
        "message" => {"type" => "string"}, "provides" => {"type" => "array", "items" => {"type" => "string"}},
        "failures" => {"type" => "integer", "format" => "int64"}, "lastFailure" => {"type" => "string"},
        "time" => {"type" => "string", "format" => "date-time"}
      }
    }

    # The API type extensions are stored as.  A CustomResourceDefinition, so
    # the built-in API surface stays exactly upstream's and every client that
    # speaks to Kubernetes can read and write extensions unchanged.
    CRD = {
      "apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
      "metadata" => {"name" => CRD_NAME},
      "spec" => {
        "group" => GROUP, "scope" => "Cluster",
        "names" => {"plural" => RESOURCE, "singular" => "extension", "kind" => KIND, "listKind" => "ExtensionList",
                    "shortNames" => ["rext"]},
        "versions" => [{
          "name" => VERSION, "served" => true, "storage" => true,
          "subresources" => {"status" => {}},
          "additionalPrinterColumns" => [
            {"name" => "Scheduler", "type" => "boolean", "jsonPath" => ".status.components.scheduler.loaded"},
            {"name" => "Admission", "type" => "boolean", "jsonPath" => ".status.components.admission.loaded"},
            {"name" => "Controller", "type" => "boolean", "jsonPath" => ".status.components.controller.loaded"},
            {"name" => "Age", "type" => "date", "jsonPath" => ".metadata.creationTimestamp"}
          ],
          "schema" => {"openAPIV3Schema" => {
            "type" => "object", "required" => ["spec"],
            "properties" => {
              "spec" => {"type" => "object", "required" => ["source"],
                         "properties" => {"source" => {"type" => "string", "minLength" => 1, "maxLength" => MAX_SOURCE_BYTES}}},
              "status" => {"type" => "object",
                           "properties" => {"components" => {"type" => "object", "additionalProperties" => component_status}}}
            }
          }}
        }]
      }
    }.freeze

    # The Extension object for a source file.
    def self.manifest(name, source)
      {"apiVersion" => API_VERSION, "kind" => KIND, "metadata" => {"name" => name}, "spec" => {"source" => source}}
    end
  end
end
