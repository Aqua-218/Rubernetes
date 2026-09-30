# frozen_string_literal: true

source "https://rubygems.org"

ruby "3.4.11"

gemspec

gem "google-protobuf", "4.36.0"
gem "grpc", "1.83.0"
gem "grpc-tools", "1.83.0"
gem "minitest", "~> 5.25"
gem "rake", "~> 13.2"
gem "rbs", "~> 3.8"
gem "rexml", "~> 3.4"
# Ruby 3.4.11's default json; json 3.x rejects duplicate keys and changes
# generator errors, which the strict codec and audit paths handle themselves.
gem "json", "= 2.9.1"

group :development do
  gem "rubocop", "~> 1.91", require: false
  gem "rubocop-minitest", require: false
  gem "rubocop-performance", require: false
  gem "rubocop-rake", require: false
end
