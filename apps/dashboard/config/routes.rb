# frozen_string_literal: true

Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  root "overview#index"

  # Prometheus-compatible HTTP API (what Grafana and promtool speak).
  namespace :api do
    scope "v1", module: "v1", as: "v1" do
      match "query", to: "query#instant", via: %i[get post]
      match "query_range", to: "query#range", via: %i[get post]
      match "series", to: "query#series", via: %i[get post]
      get "labels", to: "query#labels"
      get "label/:name/values", to: "query#label_values", constraints: {name: /[^\/]+/}
      get "metadata", to: "query#metadata"
      get "targets", to: "status#targets"
      get "rules", to: "status#rules"
      get "alerts", to: "status#alerts"
      get "status/buildinfo", to: "status#buildinfo"
      get "status/tsdb", to: "status#tsdb"
      get "status/runtimeinfo", to: "status#runtimeinfo"
      get "status/config", to: "status#config"
    end
  end

  # Prometheus-style pages.
  get "graph", to: "graph#index"
  get "targets", to: "monitoring#targets"
  get "rules", to: "monitoring#rules"
  get "alerts", to: "monitoring#alerts"
  get "status", to: "monitoring#status"

  # Cluster browser.
  resources :nodes, only: %i[index show], constraints: {id: /[^\/]+/}
  resources :namespaces, only: %i[index show], constraints: {id: /[^\/]+/} do
    resources :pods, only: %i[index show destroy], constraints: {id: /[^\/]+/} do
      member do
        get :logs
        get :yaml
      end
    end
    resources :events, only: %i[index]
    Dashboard::ResourceCatalog::NAMESPACED.each_key do |kind|
      resources kind, only: %i[index show destroy], controller: "resources", defaults: {kind: kind.to_s}, constraints: {id: /[^\/]+/} do
        member do
          get :yaml
          post :scale
          post :restart
        end
      end
    end
  end
  get "events", to: "events#all"
  Dashboard::ResourceCatalog::CLUSTER.each_key do |kind|
    next if kind == :nodes || kind == :namespaces

    resources kind, only: %i[index show], controller: "resources", defaults: {kind: kind.to_s, cluster: true}, constraints: {id: /[^\/]+/} do
      member { get :yaml }
    end
  end
end
