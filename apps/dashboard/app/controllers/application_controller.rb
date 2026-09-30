# frozen_string_literal: true

class ApplicationController < ActionController::Base
  allow_browser versions: :modern
  before_action :authenticate!

  helper_method :runtime, :client, :writes_allowed?, :age, :namespaces_for_nav, :api_available?

  rescue_from StandardError, with: :render_error

  private

  def runtime
    Dashboard::Runtime.current
  end

  def client
    runtime.client or raise Dashboard::Errors::Unavailable, "the Kubernetes API client is not configured: #{runtime.errors[:client]}"
  end

  def api_available?
    !runtime.client.nil?
  end

  def writes_allowed?
    Dashboard::Config.writes_allowed?
  end

  def require_writes!
    return if writes_allowed?

    raise Dashboard::Errors::Forbidden, "write actions are disabled (DASHBOARD_ALLOW_WRITES=0)"
  end

  # HTTP basic auth with the configured password; any user name.
  def authenticate!
    password = Dashboard::Config.password
    return if password.nil?

    authenticate_or_request_with_http_basic("Rubernetes dashboard") do |_user, given|
      ActiveSupport::SecurityUtils.secure_compare(given.to_s, password)
    end
  end

  def namespaces_for_nav
    return [] unless api_available?

    Rails.cache.fetch("namespaces-nav", expires_in: 15.seconds) do
      Array(client.get("namespaces")["items"]).map { |ns| ns.dig("metadata", "name") }.sort
    end
  rescue StandardError
    []
  end

  # "5m", "3h", "2d" like kubectl.
  def age(timestamp)
    return "" if timestamp.blank?

    seconds = (Time.now.utc - Time.iso8601(timestamp.to_s)).to_i
    return "#{seconds}s" if seconds < 120
    return "#{seconds / 60}m" if seconds < 2 * 3600
    return "#{seconds / 3600}h" if seconds < 2 * 86_400

    "#{seconds / 86_400}d"
  rescue ArgumentError
    timestamp.to_s
  end

  def render_error(error)
    status = case error
             when Dashboard::Errors::Forbidden then :forbidden
             when Dashboard::Errors::Unavailable then :service_unavailable
             when ActionController::RoutingError then :not_found
             else
               if error.instance_of?(::Rubernetes::Client::APIError) && error.respond_to?(:response) && error.response
                 code = error.response.status.to_i
                 code.between?(400, 599) ? code : :bad_gateway
               else
                 :internal_server_error
               end
             end
    Rails.logger.error("#{error.class}: #{error.message}\n#{Array(error.backtrace).first(8).join("\n")}") unless status == :not_found
    @error = error
    respond_to do |format|
      format.html { render "errors/show", status: status }
      format.json { render json: {"status" => "error", "errorType" => error.class.name, "error" => error.message}, status: status }
      format.any { render plain: "#{error.class}: #{error.message}", status: status }
    end
  end
end
