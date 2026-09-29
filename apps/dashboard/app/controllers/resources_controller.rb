# frozen_string_literal: true

# Generic list/detail/YAML for every kind in Dashboard::ResourceCatalog, plus
# scale and rollout-restart for the scalable workloads.
class ResourcesController < ApplicationController
  before_action :load_entry

  def index
    @objects = Array(client.get(@entry.resource, namespace: @namespace, api_version: @entry.api_version)["items"])
               .sort_by { |o| o.dig("metadata", "name") }
  end

  def show
    @object = fetch
    @yaml = @object.to_yaml
    @pods = related_pods
    @events = Array(client.get("events", namespace: @namespace,
                               query: {"fieldSelector" => "involvedObject.name=#{params[:id]},involvedObject.kind=#{@entry.kind}"})["items"])
              .sort_by { |e| e["lastTimestamp"] || "" }.reverse.first(30)
  rescue StandardError => e
    raise e unless @object

    @events = []
  end

  def yaml
    render plain: fetch.to_yaml, content_type: "text/yaml"
  end

  def scale
    require_writes!
    raise Dashboard::Errors::BadRequest, "#{@entry.kind} cannot be scaled" unless @entry.scalable

    replicas = Integer(params.require(:replicas))
    raise Dashboard::Errors::BadRequest, "replicas must be >= 0" if replicas.negative?

    client.patch(@entry.resource, params[:id], {"spec" => {"replicas" => replicas}}, namespace: @namespace,
                                                                                        api_version: @entry.api_version, type: :merge)
    redirect_to resource_path, notice: "#{@entry.kind} #{params[:id]} scaled to #{replicas}"
  end

  # kubectl rollout restart: bump the pod template annotation.
  def restart
    require_writes!
    raise Dashboard::Errors::BadRequest, "#{@entry.kind} has no pod template to restart" unless %w[Deployment StatefulSet DaemonSet].include?(@entry.kind)

    patch = {"spec" => {"template" => {"metadata" => {"annotations" => {"kubectl.kubernetes.io/restartedAt" => Time.now.utc.iso8601}}}}}
    client.patch(@entry.resource, params[:id], patch, namespace: @namespace, api_version: @entry.api_version, type: :strategic)
    redirect_to resource_path, notice: "#{@entry.kind} #{params[:id]} restart requested"
  end

  def destroy
    require_writes!
    client.delete(@entry.resource, params[:id], namespace: @namespace, api_version: @entry.api_version)
    redirect_to polymorphic_index_path, notice: "#{@entry.kind} #{params[:id]} deletion requested"
  end

  private

  def load_entry
    @kind = params[:kind].to_s
    @entry = Dashboard::ResourceCatalog.find(@kind) or raise ActionController::RoutingError, "unknown kind #{@kind}"
    @namespace = params[:cluster] ? nil : params[:namespace_id]
  end

  def fetch
    client.get(@entry.resource, params[:id], namespace: @namespace, api_version: @entry.api_version)
  end

  def related_pods
    selector = @object.dig("spec", "selector", "matchLabels") || (@entry.kind == "Service" ? @object.dig("spec", "selector") : nil)
    return [] if selector.blank? || @namespace.nil?

    label_selector = selector.map { |k, v| "#{k}=#{v}" }.join(",")
    Array(client.get("pods", namespace: @namespace, query: {"labelSelector" => label_selector})["items"])
  rescue StandardError
    []
  end

  def resource_path
    @namespace ? "/namespaces/#{@namespace}/#{@kind}/#{params[:id]}" : "/#{@kind}/#{params[:id]}"
  end

  def polymorphic_index_path
    @namespace ? "/namespaces/#{@namespace}/#{@kind}" : "/#{@kind}"
  end
end
