# frozen_string_literal: true

class NodesController < ApplicationController
  def index
    @nodes = Array(client.get("nodes")["items"]).sort_by { |n| n.dig("metadata", "name") }
    @pods_by_node = Array(client.get("pods", namespace: :all)["items"]).group_by { |p| p.dig("spec", "nodeName") }
  end

  def show
    @node = client.get("nodes", params[:id])
    @pods = Array(client.get("pods", query: {"fieldSelector" => "spec.nodeName=#{params[:id]}"})["items"])
    @events = Array(client.get("events", query: {"fieldSelector" => "involvedObject.kind=Node,involvedObject.name=#{params[:id]}"})["items"])
              .sort_by { |e| e["lastTimestamp"] || "" }.reverse.first(30)
    @yaml = @node.to_yaml
    @usage = node_usage(params[:id])
  end

  private

  # Latest CPU/memory usage from the kubelet resource metrics we scrape.
  def node_usage(name)
    engine = runtime.engine
    cpu = engine.query("rate(node_cpu_usage_seconds_total{node=\"#{name}\"}[2m])").value.first&.point&.last
    memory = engine.query("node_memory_working_set_bytes{node=\"#{name}\"}").value.first&.point&.last
    {"cpu_cores" => cpu, "memory_bytes" => memory}
  rescue StandardError
    {}
  end
end
