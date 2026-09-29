# frozen_string_literal: true

# The expression browser: the page only renders the form; results come from
# /api/v1/query and /api/v1/query_range through graph.js.
class GraphController < ApplicationController
  def index
    @expression = params[:g0_expr].presence || params[:expr].presence || ""
    @range = params[:g0_range_input].presence || params[:range].presence || "1h"
    @tab = params[:g0_tab].presence || params[:tab].presence || "graph"
    @metric_names = runtime.store.label_values("__name__").first(5000)
  end
end
