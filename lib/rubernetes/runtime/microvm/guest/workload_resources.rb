# frozen_string_literal: true

require "json"

require_relative "../container_files"
require_relative "../errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      module Guest
        # Resolve guest disks, image paths and kubelet files for container operations.
        module WorkloadResources
          def container_create(params)
            @mutex.synchronize do
              require_phase!(%w[identified networked])
              sandbox_id = @sandboxes.fetch(params["sandbox_id"]) { raise ProtocolError, "unknown sandbox #{params["sandbox_id"]}" }
              spec = translate_container_spec(require_hash(params, "spec"))
              id = require_string(params, "id")
              create_files = prepare_container_files(id, params["files"]) if params.key?("files")
              container = native.create_container(sandbox_id, spec, id: id, request_id: params["request_id"])
              {"id" => container.id, "state" => container.state.to_s}
            rescue StandardError
              FileUtils.rm_rf(ContainerFiles.directory(id)) if create_files
              raise
            end
          end

          def container_remove(params)
            @mutex.synchronize do
              id = require_string(params, "id")
              native.remove_container(id, request_id: params["request_id"])
              FileUtils.rm_rf(ContainerFiles.directory(id))
              {"id" => id, "state" => "removed"}
            end
          end

          def container_status(params)
            @mutex.synchronize do
              id = require_string(params, "id")
              status = plain(native.container_status(id))
              path = File.join(ContainerFiles.directory(id), ContainerFiles::TERMINATION)
              if status["state"] == "stopped" && File.file?(path)
                message = File.open(path, "rb") do |file|
                  file.seek([file.size - 4096, 0].max)
                  file.read(4096).to_s.force_encoding(Encoding::UTF_8).scrub
                end
                unless message.empty?
                  status["message"] = message
                  status["terminated"]["message"] = message if status["terminated"]
                end
              end
              status
            end
          end

          private

          def translate_container_spec(spec)
            translated = JSON.parse(JSON.generate(spec))
            image = translated["resolved_image"]
            image["rootfs"] = image_mount_path(image["digest"]) if image.is_a?(Hash) && image["digest"].to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
            Array(translated["mounts"]).map! do |mount|
              next mount unless mount["device"] == true || mount["volume_device"] == true

              name = mount["name"]
              volume = @block_volumes[name]
              unless mount["device"] == true && mount["volume_device"] == true && volume && volume["readonly"] == (mount["readonly"] == true)
                raise PolicyError, "device mapping #{name.inspect} is not a prepared microVM block volume"
              end

              mount.slice("name", "destination", "device").merge(
                "source" => volume["device"], "readonly" => volume["readonly"], "propagation" => "None",
                "permissions" => volume["readonly"] ? "r" : "mrw"
              )
            end
            translated
          end

          def prepare_container_files(id, files)
            raise ProtocolError, "invalid kubelet-generated container files" unless files.is_a?(Hash) && (files.keys - ContainerFiles::NAMES).empty?

            return false if files.empty?

            directory = ContainerFiles.directory(id)
            return false if File.directory?(directory)

            FileUtils.mkdir_p(ContainerFiles::ROOT, mode: 0o700)
            Dir.mkdir(directory, 0o700)
            created = true
            write_files(files.map do |name, content|
              {"path" => File.join(directory, name), "content" => content, "mode" => name == ContainerFiles::TERMINATION ? 0o666 : 0o644}
            end)
            true
          rescue StandardError
            FileUtils.rm_rf(directory) if created
            raise
          end

          def resolve_block_volumes(volumes)
            volumes.to_h do |name, volume|
              slot = volume["slot"] if volume.is_a?(Hash)
              raise ProtocolError, "block volume #{name.inspect} has an invalid virtio slot" unless slot.is_a?(Integer) && slot.between?(2, 18)

              # Firecracker gives each virtio MMIO device an ACPI UID based on
              # its IRQ. The UID identifies the slot independently of /dev/vd*
              # enumeration in the pinned kernel.
              nodes = Dir.glob("/sys/bus/acpi/devices/LNRO0005:*/uid").filter_map do |uid|
                File.dirname(uid) if File.read(uid).strip == slot.to_s
              end.flat_map { |path| Dir.glob("#{path}/physical_node/virtio*/block/*") }
              device = "/dev/#{File.basename(nodes.first)}" if nodes.one?
              raise ProtocolError, "block volume #{name.inspect} is missing from virtio slot #{slot}" unless device && File.blockdev?(device)

              readonly = volume["readonly"] == true
              unless File.read(File.join(nodes.first, "ro")).strip == (readonly ? "1" : "0")
                raise ProtocolError, "block volume #{name.inspect} has an unexpected read-only mode"
              end

              File.chown(Integer(volume.fetch("uid")), Integer(volume.fetch("gid")), device)
              File.chmod(Integer(volume.fetch("mode")) & 0o777, device)
              [name, {"device" => device, "readonly" => readonly}]
            rescue SystemCallError => error
              raise ProtocolError, "could not read block volume #{name.inspect}: #{error.message}"
            end
          end
        end
      end
    end
  end
end
