# frozen_string_literal: true

require_relative "errors"
require_relative "canonical"

module Rubernetes
  module Consensus
    # Cluster configuration with joint consensus (Raft section 6).  A
    # configuration is either simple ({voters}) or joint ({old voters, new
    # voters}); a joint configuration requires a majority of both sets.
    # Single-server changes are deliberately not implemented (spec 5.3.7).
    class Membership
      attr_reader :voters, :old_voters, :learners

      def self.from_h(value)
        raise MembershipError, "membership must be an object" unless value.is_a?(Hash)

        new(voters: value.fetch("voters"), old_voters: value["old_voters"], learners: value["learners"] || [])
      end

      def self.simple(voters, learners: [])
        new(voters: voters, learners: learners)
      end

      def initialize(voters:, old_voters: nil, learners: [])
        @voters = normalize_ids(voters, "voters")
        @old_voters = old_voters.nil? ? nil : normalize_ids(old_voters, "old_voters")
        @learners = normalize_ids(learners, "learners")
        raise MembershipError, "voters must not be empty" if @voters.empty?
        raise MembershipError, "old_voters must not be empty in a joint configuration" if @old_voters && @old_voters.empty?

        overlap = @learners & @voters
        raise MembershipError, "learners overlap voters: #{overlap.to_a.sort.join(", ")}" unless overlap.empty?

        freeze
      end

      def joint?
        !@old_voters.nil?
      end

      def members
        (@voters | (@old_voters || Set.new) | @learners).to_a.sort
      end

      def voter?(id)
        @voters.include?(id) || (@old_voters&.include?(id) || false)
      end

      def member?(id)
        voter?(id) || @learners.include?(id)
      end

      def peers_of(id)
        members - [id]
      end

      # Does the set of node IDs form a quorum?  In a joint configuration a
      # majority of both the old and the new voter sets is required.
      def quorum?(ids)
        set = ids.is_a?(Set) ? ids : Set.new(ids)
        majority?(set, @voters) && (@old_voters.nil? || majority?(set, @old_voters))
      end

      # Largest index replicated on a quorum, given a map of node => match index.
      def committed_index(match_indexes)
        candidate = quorum_index(match_indexes, @voters)
        return candidate if @old_voters.nil?

        [candidate, quorum_index(match_indexes, @old_voters)].min
      end

      def enter_joint(new_voters, learners: @learners)
        raise MembershipError, "already in a joint configuration" if joint?

        Membership.new(voters: new_voters, old_voters: @voters, learners: learners)
      end

      def leave_joint
        raise MembershipError, "not in a joint configuration" unless joint?

        Membership.new(voters: @voters, learners: @learners)
      end

      def to_h
        hash = {"voters" => @voters.to_a.sort, "learners" => @learners.to_a.sort}
        hash["old_voters"] = @old_voters.to_a.sort if @old_voters
        hash
      end

      def ==(other)
        other.is_a?(Membership) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end

      private

      def majority?(set, voters)
        (set & voters).length * 2 > voters.length
      end

      def quorum_index(match_indexes, voters)
        indexes = voters.map { |id| Integer(match_indexes.fetch(id, 0)) }.sort.reverse
        indexes[voters.length / 2] || 0
      end

      def normalize_ids(ids, label)
        set = Set.new
        Array(ids).each do |id|
          value = String(id)
          raise MembershipError, "#{label} contains an empty node id" if value.empty?
          raise MembershipError, "#{label} contains duplicate node id #{value}" if set.include?(value)

          set << value
        end
        set.freeze
      end
    end
  end
end
