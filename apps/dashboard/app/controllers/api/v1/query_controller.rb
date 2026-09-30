# frozen_string_literal: true

module Api
  module V1
    class QueryController < BaseController
      # GET|POST /api/v1/query?query=...&time=...
      def instant
        expression = params.require(:query)
        time = parse_time(params[:time], default: engine.now_ms)
        result = engine.query(expression, time)
        success(result.to_api)
      end

      # GET|POST /api/v1/query_range?query=...&start=...&end=...&step=...
      def range
        expression = params.require(:query)
        start_ms = parse_time(params.require(:start))
        end_ms = parse_time(params.require(:end))
        step_ms = parse_duration_ms(params.require(:step))
        unless step_ms.positive?
          raise Dashboard::Errors::BadRequest,
                "invalid parameter \"step\": zero or negative query resolution step widths are not accepted"
        end
        raise Dashboard::Errors::BadRequest, "invalid parameter \"end\": end timestamp must not be before start time" if end_ms < start_ms

        result = engine.query_range(expression, start_ms, end_ms, step_ms)
        success(result.to_api)
      end

      # GET|POST /api/v1/series?match[]=...
      def series
        sets = matcher_sets(params[:match] || params["match[]"])
        raise Dashboard::Errors::BadRequest, "no match[] parameter provided" if sets.empty?

        start_ms = parse_time(params[:start], default: engine.now_ms - (60 * 60 * 1000))
        end_ms = parse_time(params[:end], default: engine.now_ms)
        success(engine.series(sets, start_ms, end_ms))
      end

      # GET /api/v1/labels
      def labels
        sets = matcher_sets(params[:match] || params["match[]"])
        names = if sets.empty?
                  store.label_names
                else
                  sets.flat_map do |m|
                    store.label_names(m.map do |x|
                                        Tsdb::Store::Matcher.new(name: x.name, op: x.op, value: x.value)
                                      end)
                  end.uniq.sort
                end
        success(names)
      end

      # GET /api/v1/label/:name/values
      def label_values
        name = params[:name]
        raise Dashboard::Errors::BadRequest, "invalid label name: #{name.inspect}" unless name.match?(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)

        sets = matcher_sets(params[:match] || params["match[]"])
        values = if sets.empty?
                   store.label_values(name)
                 else
                   sets.flat_map do |m|
                     store.label_values(name, m.map do |x|
                       Tsdb::Store::Matcher.new(name: x.name, op: x.op, value: x.value)
                     end)
                   end.uniq.sort
                 end
        success(values)
      end

      # GET /api/v1/metadata?metric=...
      def metadata
        all = runtime.scraper.metadata
        all = all.select { |name, _| name == params[:metric] } if params[:metric].present?
        limit = params[:limit].present? ? params[:limit].to_i : nil
        all = all.first(limit).to_h if limit
        success(all)
      end
    end
  end
end
