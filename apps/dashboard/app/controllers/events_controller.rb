# frozen_string_literal: true

class EventsController < ApplicationController
  def index
    @namespace = params[:namespace_id]
    @events = sorted(Array(client.get("events", namespace: @namespace)["items"]))
  end

  def all
    @events = sorted(Array(client.get("events", namespace: :all)["items"]))
    render :index
  end

  private

  def sorted(events)
    events = events.select { |e| e["type"] == "Warning" } if params[:type] == "Warning"
    events.sort_by { |e| e["lastTimestamp"] || e.dig("metadata", "creationTimestamp") || "" }.last(300).reverse
  end
end
