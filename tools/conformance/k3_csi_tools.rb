# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "open3"
require "tmpdir"

module Conformance
  module K3CSITools
    # Linux amd64 manifests and executable hashes for the pinned Kubernetes
    # HostPath test deployment and NFS CSI v4.11.0. An optional layer digest
    # identifies the executable when metadata occupies the last layer.
    IMAGES = {
      "hostpathplugin" => %w[
        cf08eec6a810b81299e6342719fb77c4c4072fbd43541c30ae1a4ca47a93c326
        a9001be9948de991e22b959aa9c2345a76134a01fcb3efd53be3043fb3d7f930
      ],
      "nfsplugin" => %w[
        3a404b8b22fc0e661a0ab00175252a0d3071c1e0b1aaa0636b4da163e00ed038
        aa0c76f3c9e6bffd957c7305004d6dd481fc10d2b4cbd2037c603010942ca260
        1fec665d483ed863e577f43d747b0c4a416021d591448334071defb82c680343
      ],
      "csi-attacher" => %w[
        4f6b1289ffe62dbe3d2317dd938cd9dd3fb0a7c0088d505cde4effa1e0771dc2
        e212ac6bafff4e89dc73db8363d675c3a2987eff7108b8044ef55b693d5fc595
      ],
      "csi-provisioner" => %w[
        60751c039762f43183f9ec93ed137ea5acae9485f2b8a0fd0e1f26aed9979746
        cdb4217b0f70e33e8af588afe3b7c04540a87e55cefc819bfab7c9aa3bf7da7e
      ],
      "csi-node-driver-registrar" => %w[
        aeecba5b171b50558bab359fdb8e28b9da185f666cef35cd87ac9784e51956c5
        00256e4718a66f2cb77a8c8aa61672d42b804a1c33e52f78f48f5842df9face2
      ],
      "csi-resizer" => %w[
        69e7bf7d929e5d98a5a74e753b45220e6e7b04f35163e48e8a5958bf1d819b4c
        86366c525afea4d10b11f0c60eeef547dbff7206964f262cc1332edd57740276
      ],
      "csi-snapshotter" => %w[
        f4d58334dc3c0873e544f110a188be47e224ff7e99c6400d2fd7b35de9b962eb
        8976dd2fffb5e5a65eddc7c70d212f5b18d486037f8ae7cc4b9c8e0879a2c37c
      ],
      "snapshot-controller" => %w[
        c6ed5c488dc72a01e7d69caf4d6efe44cb5fecd08fac1a037626171bf90482d1
        e592115a873f74c3e7a24bf228c699501ed49bbac9320948874d90c734ae190e
      ]
    }.freeze
    SNAPSHOT_TOOLS = %w[csi-snapshotter snapshot-controller].freeze

    module_function

    def install(directory, snapshots: false, expansion: false, nfs: false)
      FileUtils.mkdir_p(directory)
      names = nfs ? %w[nfsplugin csi-provisioner csi-node-driver-registrar] : IMAGES.keys - ["nfsplugin"]
      names -= SNAPSHOT_TOOLS unless snapshots
      names -= ["csi-resizer"] unless expansion
      names.to_h do |name|
        image_digest, binary_digest, binary_layer = IMAGES.fetch(name)
        executable = File.join(directory, name)
        extract(name, image_digest, executable, binary_layer: binary_layer) unless verified?(executable, binary_digest)
        raise "the extracted #{name} does not match its pinned digest" unless verified?(executable, binary_digest)

        [name, executable]
      end
    end

    def verified?(path, digest)
      File.executable?(path) && Digest::SHA256.file(path).hexdigest == digest
    end

    def extract(name, digest, executable, binary_layer: nil)
      Dir.mktmpdir("image-", File.dirname(executable)) do |directory|
        reference = "docker://registry.k8s.io/sig-storage/#{name}@sha256:#{digest}"
        _, error, status = Open3.capture3("skopeo", "copy", "--retry-times", "3", reference, "dir:#{directory}")
        raise "cannot fetch #{reference}: #{error.strip}" unless status.success?

        manifest = JSON.parse(File.read(File.join(directory, "manifest.json")))
        layers = manifest.fetch("layers").map { |entry| entry.fetch("digest").delete_prefix("sha256:") }
        layer = binary_layer || layers.last
        raise "cannot find the pinned #{name} executable layer in #{reference}" unless layers.include?(layer)

        binary = File.join(directory, name)
        ok = system("tar", "-xf", File.join(directory, layer), "-C", directory, "--", name, out: File::NULL)
        raise "cannot extract #{name} from #{reference}" unless ok

        FileUtils.chmod(0o755, binary)
        File.rename(binary, executable)
      end
    end
  end
end
