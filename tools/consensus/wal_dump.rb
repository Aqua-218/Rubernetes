#!/usr/bin/env ruby
# frozen_string_literal: true

# Print the Raft commands in a WAL segment that touch a key (or everything
# when no needle is given).  Reading the WAL settles "did the write reach
# consensus, and what did it carry" in one step -- which is how the deleted
# namespaces that came back Active were traced to a status apply that
# re-created them, before any theory about raft itself.
#
#   bundle exec ruby -Ilib tools/consensus/wal_dump.rb <path.rbwal> [needle]

require "rubernetes/consensus"

path = ARGV[0] or abort("usage: wal_dump.rb <wal file> [needle]")
needle = ARGV[1]
records, report = Rubernetes::Consensus::WAL.read(path)
puts "records=#{records.length} torn_tail_bytes=#{report.torn_tail_bytes}"
records.each do |record|
  payload = record.payload
  entries = payload.is_a?(Hash) ? (payload["entries"] || [payload]) : Array(payload)
  entries.each do |entry|
    next unless entry.is_a?(Hash)
    next if needle && !entry.inspect.include?(needle)

    command = entry["command"] || entry["data"]
    object = command.is_a?(Hash) ? command["object"] : nil
    managers = object && Array(object.dig("metadata", "managedFields")).map { |field| field["manager"] }
    puts format("idx=%-8s term=%-3s type=%-7s key=%s expected_rv=%s dt=%s phase=%s managers=%s",
                entry["index"], entry["term"], command.is_a?(Hash) ? command["type"] : command.class,
                command.is_a?(Hash) ? command["key"] : nil,
                command.is_a?(Hash) ? command["expected_resource_version"] : nil,
                object&.dig("metadata", "deletionTimestamp"), object&.dig("status", "phase"), managers.inspect)
  end
end
