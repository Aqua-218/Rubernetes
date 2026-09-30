# frozen_string_literal: true

class PodsController < ApplicationController
  before_action :load_namespace

  def index
    @pods = Array(client.get("pods", namespace: @namespace)["items"]).sort_by { |p| p.dig("metadata", "name") }
    @filter = params[:q].to_s
    @pods = @pods.select { |p| p.dig("metadata", "name").include?(@filter) } unless @filter.empty?
  end

  def show
    @pod = client.get("pods", params[:id], namespace: @namespace)
    @events = Array(client.get("events", namespace: @namespace,
                                         query: {"fieldSelector" => "involvedObject.name=#{params[:id]},involvedObject.kind=Pod"})["items"])
      .sort_by { |e| e["lastTimestamp"] || "" }.reverse
    @containers = Array(@pod.dig("spec", "initContainers")).map { |c| c.merge("_kind" => "init") } +
                  Array(@pod.dig("spec", "containers")).map { |c| c.merge("_kind" => "app") }
    @statuses = (Array(@pod.dig("status", "initContainerStatuses")) + Array(@pod.dig("status", "containerStatuses"))).to_h do |s|
      [s["name"], s]
    end
    @yaml = @pod.to_yaml
    @usage = container_usage
  end

  def logs
    container = params[:container].presence || first_container
    tail = (params[:tail].presence || 500).to_i.clamp(1, 10_000)
    query = {"container" => container, "tailLines" => tail.to_s}
    query["previous"] = "true" if params[:previous] == "1"
    query["timestamps"] = "true" if params[:timestamps] == "1"
    response = client.raw(:get, "/api/v1/namespaces/#{@namespace}/pods/#{params[:id]}/log", query: query, raise_for_status: false)
    @container = container
    @tail = tail
    @status = response.status.to_i
    @text = response.body.to_s.force_encoding(Encoding::UTF_8).scrub
    @pod = client.get("pods", params[:id], namespace: @namespace)
    respond_to do |format|
      format.html
      format.text { render plain: @text, status: @status == 200 ? :ok : :bad_gateway }
    end
  end

  def yaml
    object = client.get("pods", params[:id], namespace: @namespace)
    render plain: object.to_yaml, content_type: "text/yaml"
  end

  def destroy
    require_writes!
    grace = params[:grace].presence
    options = grace ? {"gracePeriodSeconds" => grace.to_i} : nil
    client.delete("pods", params[:id], namespace: @namespace, options: options)
    redirect_to namespace_pods_path(@namespace), notice: "Pod #{params[:id]} deletion requested"
  end

  private

  def load_namespace
    @namespace = params[:namespace_id]
  end

  def first_container
    pod = client.get("pods", params[:id], namespace: @namespace)
    pod.dig("spec", "containers", 0, "name")
  end

  def container_usage
    engine = runtime.engine
    cpu = engine.query("rate(container_cpu_usage_seconds_total{namespace=\"#{@namespace}\",pod=\"#{params[:id]}\"}[2m])").value
    memory = engine.query("container_memory_working_set_bytes{namespace=\"#{@namespace}\",pod=\"#{params[:id]}\"}").value
    {"cpu" => cpu.to_h { |s| [s.metric["container"], s.point[1]] }, "memory" => memory.to_h { |s| [s.metric["container"], s.point[1]] }}
  rescue StandardError
    {"cpu" => {}, "memory" => {}}
  end
end
