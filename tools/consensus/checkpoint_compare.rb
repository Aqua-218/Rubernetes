#!/usr/bin/env ruby
# frozen_string_literal: true

# Compare the apply checkpoints of several apiserver replicas.  Every
# replica logs "consensus.apply_checkpoint" (index, revision, live objects,
# effect counters, running digest) every RUBERNETES_RAFT_CHECKPOINT_ENTRIES
# applies; at the same index every replica must report the same digest,
# revision and object count, or the replicas have diverged.  Any
# "consensus.apply_invariant_violation" (live objects != creates - deletes)
# and "consensus.ack_without_object" (a write acknowledged that cannot be
# read back) is listed as well.  Exit status 1 when anything is wrong.
#
#   bundle exec ruby tools/consensus/checkpoint_compare.rb logs/apiserver-control-*.log

require "json"

paths = ARGV
abort("usage: checkpoint_compare.rb <apiserver log>...") if paths.empty?

checkpoints = Hash.new { |hash, index| hash[index] = {} }
problems = []
paths.each do |path|
  name = File.basename(path, ".log")
  File.foreach(path) do |line|
    next unless line.include?("consensus.")

    record = begin
      JSON.parse(line)
    rescue JSON::ParserError
      next
    end
    case record["event"]
    when "consensus.apply_checkpoint"
      checkpoints[record["index"]][name] = record
    when "consensus.apply_invariant_violation", "consensus.ack_without_object"
      problems << "#{name} #{record["timestamp"]} #{record["event"]} #{record.reject { |key, _| %w[timestamp level event process].include?(key) }}"
    end
  end
end

mismatches = 0
checkpoints.keys.sort.each do |index|
  entries = checkpoints[index]
  next if entries.length < 2

  fields = entries.transform_values { |record| record.values_at("digest", "revision", "objects") }
  next if fields.values.uniq.length == 1

  mismatches += 1
  puts "index #{index}: replicas disagree"
  entries.each { |name, record| puts "  #{name}: digest=#{record["digest"]} revision=#{record["revision"]} objects=#{record["objects"]} at #{record["timestamp"]}" }
end

compared = checkpoints.count { |_index, entries| entries.length >= 2 }
puts "checkpoints: #{checkpoints.length} indexes, #{compared} compared across replicas, #{mismatches} mismatches"
puts "problems: #{problems.length}"
problems.each { |problem| puts "  #{problem}" }
exit(mismatches.zero? && problems.empty? ? 0 : 1)
