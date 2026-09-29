# frozen_string_literal: true

module Prom
  # One scrape target: how to fetch it and the labels every sample gets.
  #
  # +fetch+ is a callable returning [status, body_text] (or raising); the
  # scraper never cares whether the bytes came over the API server proxy, a
  # mutually authenticated control-plane port, or plain HTTP to a Pod IP.
  Target = Struct.new(:job, :instance, :labels, :fetch, :url, keyword_init: true) do
    def key = "#{job}|#{instance}|#{url}"
  end
end
