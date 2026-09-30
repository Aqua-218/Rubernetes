# frozen_string_literal: true

module Api
  module V1
    # Prometheus HTTP API envelope: {"status":"success","data":...} and
    # {"status":"error","errorType":...,"error":...} with the same status
    # codes Prometheus uses (400 bad_data, 422 execution, 503 unavailable).
    class BaseController < ApplicationController
      skip_before_action :verify_authenticity_token
      rescue_from StandardError, with: :api_error

      private

      def success(data, warnings: [])
        payload = {"status" => "success", "data" => data}
        payload["warnings"] = warnings unless warnings.empty?
        render json: payload
      end

      def api_error(error)
        type, status = case error
                       when Promql::ParseError, Dashboard::Errors::BadRequest, ArgumentError then ["bad_data", 400]
                       when Promql::EvalError then ["execution", 422]
                       when Dashboard::Errors::Forbidden then ["forbidden", 403]
                       when Dashboard::Errors::Unavailable then ["unavailable", 503]
                       else ["internal", 500]
                       end
        Rails.logger.error("#{error.class}: #{error.message}") if status == 500
        render json: {"status" => "error", "errorType" => type, "error" => error.message}, status: status
      end

      # Prometheus time parameters: RFC3339 or unix seconds (fractional ok).
      def parse_time(value, default: nil)
        return default if value.blank?

        text = value.to_s
        if text.match?(/\A-?\d+(\.\d+)?\z/)
          (Float(text) * 1000).round
        else
          (Time.iso8601(text).to_f * 1000).round
        end
      rescue ArgumentError
        raise Dashboard::Errors::BadRequest, "invalid parameter \"#{text}\": cannot parse to a valid timestamp"
      end

      def parse_duration_ms(value)
        text = value.to_s
        return (Float(text) * 1000).round if text.match?(/\A\d+(\.\d+)?\z/)

        Promql::Lexer.duration_ms(text)
      rescue Promql::ParseError, ArgumentError
        raise Dashboard::Errors::BadRequest, "invalid parameter \"step\": cannot parse \"#{text}\" to a valid duration"
      end

      def matcher_sets(values)
        Array(values).map do |selector|
          node = Promql::Parser.parse(selector.to_s)
          unless node.is_a?(Promql::AST::VectorSelector)
            raise Dashboard::Errors::BadRequest, "invalid parameter \"match[]\": #{selector} is not a vector selector"
          end

          node.matchers
        end
      end

      def engine = runtime.engine
      def store = runtime.store
    end
  end
end
