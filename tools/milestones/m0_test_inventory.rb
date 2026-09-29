#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "minitest"
require "rbconfig"

ROOT = File.expand_path("../..", __dir__)

# test/test_helper requires minitest/autorun.  Discovery must register the
# exact runnable methods without executing them a second time, so suppress
# only the at_exit runner before loading the authoritative Rake test pattern.
Minitest.singleton_class.send(:define_method, :autorun) { nil }
Minitest.seed = 0

$LOAD_PATH.unshift(File.join(ROOT, "build/ext/rubernetes_linux"))
$LOAD_PATH.unshift(File.join(ROOT, "test"))
$LOAD_PATH.unshift(File.join(ROOT, "lib"))

files = Dir.glob(File.join(ROOT, "test/**/*_test.rb")).sort
files.each { |path| load(path) }

identities = Minitest::Runnable.runnables.flat_map do |runnable|
  name = runnable.name.to_s
  next [] if name.empty? || !runnable.respond_to?(:runnable_methods)

  runnable.runnable_methods.map { |method_name| [name, method_name.to_s] }
end.uniq.sort

canonical = identities.map { |classname, name| "#{classname}\0#{name}\n" }.join
document = {
  "schema_version" => 1,
  "kind" => "m0_minitest_inventory",
  "ruby" => RUBY_DESCRIPTION,
  "pattern" => "test/**/*_test.rb",
  "file_count" => files.length,
  "testcase_count" => identities.length,
  "testcase_sha256" => Digest::SHA256.hexdigest(canonical),
  "testcases" => identities.map { |classname, name| {"classname" => classname, "name" => name} }
}
puts(JSON.generate(document))
