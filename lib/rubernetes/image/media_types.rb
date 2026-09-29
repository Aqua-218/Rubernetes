# frozen_string_literal: true

module Rubernetes
  module Image
    # Media types defined by OCI Image Spec v1.1.1 and Docker schema 2.
    module MediaTypes
      OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
      OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
      OCI_IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json"
      OCI_IMAGE_LAYER = "application/vnd.oci.image.layer.v1.tar"
      OCI_IMAGE_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
      OCI_IMAGE_LAYER_ZSTD = "application/vnd.oci.image.layer.v1.tar+zstd"

      DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
      DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
      DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
      DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar"
      DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"

      OCI_MANIFEST = OCI_IMAGE_MANIFEST
      OCI_INDEX = OCI_IMAGE_INDEX
      OCI_CONFIG = OCI_IMAGE_CONFIG
      OCI_LAYER = OCI_IMAGE_LAYER
      OCI_LAYER_GZIP = OCI_IMAGE_LAYER_GZIP

      MANIFEST_TYPES = [OCI_IMAGE_MANIFEST, DOCKER_MANIFEST].freeze
      INDEX_TYPES = [OCI_IMAGE_INDEX, DOCKER_MANIFEST_LIST].freeze
      CONFIG_TYPES = [OCI_IMAGE_CONFIG, DOCKER_CONFIG].freeze
      LAYER_TYPES = [
        OCI_IMAGE_LAYER,
        OCI_IMAGE_LAYER_GZIP,
        OCI_IMAGE_LAYER_ZSTD,
        DOCKER_LAYER,
        DOCKER_LAYER_GZIP
      ].freeze

      module_function

      def manifest?(media_type)
        MANIFEST_TYPES.include?(media_type.to_s.split(";", 2).first.to_s.strip)
      end

      def index?(media_type)
        INDEX_TYPES.include?(media_type.to_s.split(";", 2).first.to_s.strip)
      end

      def config?(media_type)
        CONFIG_TYPES.include?(media_type.to_s.split(";", 2).first.to_s.strip)
      end

      def layer?(media_type)
        LAYER_TYPES.include?(media_type.to_s.split(";", 2).first.to_s.strip)
      end

      def gzip_layer?(media_type)
        [OCI_IMAGE_LAYER_GZIP, DOCKER_LAYER_GZIP].include?(media_type.to_s.split(";", 2).first.to_s.strip)
      end

      def zstd_layer?(media_type)
        media_type.to_s.split(";", 2).first.to_s.strip == OCI_IMAGE_LAYER_ZSTD
      end
    end
  end
end
