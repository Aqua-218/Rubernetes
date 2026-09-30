#!/usr/bin/env ruby
# frozen_string_literal: true

# One Raft node as a real OS process for M5 fault-injection evidence.
#
# The worker hosts a production Consensus::Server + RaftStore and exposes a
# tiny JSON-lines control protocol on a Unix socket so the probe can issue
# store operations, ask for status, request snapshots/membership changes and
# crash the process with SIGKILL from outside.  Nothing in this file changes
# consensus behaviour; it only drives the production modules.
#
# Usage: worker.rb --id a --cluster c1 --data DIR --pki DIR --listen 127.0.0.1:0 \
#                  --voters a,b,c --peers b=127.0.0.1:PORT,c=... --control /path/sock

require "json"
require "optparse"
require "socket"

$LOAD_PATH.unshift File.expand_path("../../../../lib", __dir__)
require "rubernetes/consensus"

options = {peers: {}, voters: [], host: "127.0.0.1", port: 0, timing: {}}
OptionParser.new do |parser|
  parser.on("--id ID") { |value| options[:id] = value }
  parser.on("--cluster ID") { |value| options[:cluster] = value }
  parser.on("--data DIR") { |value| options[:data] = value }
  parser.on("--pki DIR") { |value| options[:pki] = value }
  parser.on("--listen HOST:PORT") do |value|
    host, port = value.rpartition(":").values_at(0, 2)
    options[:host] = host
    options[:port] = Integer(port)
  end
  parser.on("--voters LIST") { |value| options[:voters] = value.split(",") }
  parser.on("--peers LIST") do |value|
    value.split(",").each do |pair|
      id, address = pair.split("=", 2)
      options[:peers][id] = address
    end
  end
  parser.on("--control PATH") { |value| options[:control] = value }
  parser.on("--journal PATH") { |value| options[:journal] = value }
  parser.on("--timing JSON") { |value| options[:timing] = JSON.parse(value) }
end.parse!(ARGV)

C = Rubernetes::Consensus
bundle = C::Identity.read_bundle(options.fetch(:pki))
timing = C::Node::Timing.default
timing = timing.with(**options[:timing].transform_keys(&:to_sym)) unless options[:timing].empty?
server = C::Server.new(id: options.fetch(:id), cluster_id: options.fetch(:cluster), data_directory: options.fetch(:data),
                       bundle: bundle, initial_voters: options.fetch(:voters), peers: options[:peers],
                       host: options[:host], port: options[:port], timing: timing)
journal = options[:journal] ? C::OperationJournal.new(options[:journal], component: "m5-worker-#{options[:id]}") : nil
store = C::RaftStore.new(server, journal: journal)
server.start
File.delete(options[:control]) if File.exist?(options[:control])
control = UNIXServer.new(options.fetch(:control))
# Announce readiness with the bound transport address.
$stdout.puts(JSON.generate("event" => "ready", "id" => options[:id], "address" => server.address, "pid" => Process.pid))
$stdout.flush

def handle(request, server, store, journal)
  case request["op"]
  when "status" then {"ok" => true, "status" => server.status, "revision" => store.revision}
  when "create"
    {"ok" => true, "object" => store.create(request.fetch("key"), request.fetch("object"), request_uid: request["request_uid"])}
  when "update"
    object = store.guaranteed_update(request.fetch("key"), prec: request["expected_version"],
                                                           request_uid: request["request_uid"]) do |current|
      current.merge(request.fetch("object"))
    end
    {"ok" => true, "object" => object}
  when "delete"
    {"ok" => true, "object" => store.delete(request.fetch("key"), prec: request["expected_version"], request_uid: request["request_uid"])}
  when "get"
    {"ok" => true, "object" => store.get(request.fetch("key"), resource_version: request["resource_version"])}
  when "list"
    result = store.list(request.fetch("prefix", ""))
    {"ok" => true, "items" => result.items, "resource_version" => result.resource_version}
  when "snapshot" then {"ok" => true, "snapshot" => server.snapshot!(force: true)&.to_h}
  when "membership" then {"ok" => true, "membership" => server.propose_membership(request.fetch("voters"))}
  when "transfer" then server.transfer_leadership(request.fetch("target"))
                       {"ok" => true}
  when "add_peer" then server.add_peer(request.fetch("id"), request.fetch("address"))
                       {"ok" => true}
  when "pending" then {"ok" => true, "pending" => journal ? journal.pending : []}
  when "resolve"
    journal&.record_resolution(request_id: request.fetch("request_id"), discovered: request.fetch("discovered"))
    {"ok" => true}
  when "stop" then server.stop
                   {"ok" => true, "stopped" => true}
  else {"ok" => false, "error" => "unknown op #{request["op"].inspect}"}
  end
rescue Rubernetes::Storage::Error, C::Error => error
  {"ok" => false, "error" => error.class.name, "message" => error.message,
   "resource_version" => (error.respond_to?(:resource_version) ? error.resource_version : nil)}
end

loop do
  client = control.accept
  Thread.new(client) do |socket|
    while (line = socket.gets)
      request = JSON.parse(line)
      response = handle(request, server, store, journal)
      socket.puts(JSON.generate(response))
      break if response["stopped"]
    end
  rescue IOError, SystemCallError, JSON::ParserError
    nil
  ensure
    socket.close unless socket.closed?
  end
end
