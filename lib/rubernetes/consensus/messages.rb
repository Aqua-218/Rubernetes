# frozen_string_literal: true

require_relative "errors"
require_relative "canonical"
require_relative "log"

module Rubernetes
  module Consensus
    # Raft RPC messages.  Every message carries cluster_id, the sender's
    # node_id, the sender's term and a request_id so a retransmission can be
    # deduplicated at the application layer (spec 5.3.6).
    module Messages
      TYPE_CODES = {
        "request_vote" => 1,
        "request_vote_response" => 2,
        "append_entries" => 3,
        "append_entries_response" => 4,
        "install_snapshot" => 5,
        "install_snapshot_response" => 6,
        "pre_vote" => 7,
        "pre_vote_response" => 8,
        "forward_proposal" => 9,
        "forward_proposal_response" => 10,
        "read_index" => 11,
        "read_index_response" => 12,
        "timeout_now" => 13
      }.freeze
      TYPE_NAMES = TYPE_CODES.invert.freeze

      class Message
        attr_reader :cluster_id, :from, :to, :term, :request_id

        def initialize(cluster_id:, from:, to:, term:, request_id:, **fields)
          @cluster_id = String(cluster_id)
          @from = String(from)
          @to = String(to)
          @term = Integer(term)
          @request_id = String(request_id)
          @fields = fields
        end

        def type
          self.class::TYPE
        end

        def type_code
          TYPE_CODES.fetch(type)
        end

        def [](name)
          @fields.fetch(name.to_sym)
        end

        def to_h
          {"type" => type, "cluster_id" => @cluster_id, "from" => @from, "to" => @to, "term" => @term,
           "request_id" => @request_id}.merge(@fields.transform_keys(&:to_s))
        end

        def encode
          Canonical.encode(to_h)
        end

        def ==(other)
          other.is_a?(Message) && to_h == other.to_h
        end
      end

      class RequestVote < Message
        TYPE = "request_vote"
        def last_log_index = self[:last_log_index]
        def last_log_term = self[:last_log_term]
      end

      class PreVote < Message
        TYPE = "pre_vote"
        def last_log_index = self[:last_log_index]
        def last_log_term = self[:last_log_term]
      end

      class RequestVoteResponse < Message
        TYPE = "request_vote_response"
        def granted = self[:granted]
      end

      class PreVoteResponse < Message
        TYPE = "pre_vote_response"
        def granted = self[:granted]
      end

      class AppendEntries < Message
        TYPE = "append_entries"
        def prev_log_index = self[:prev_log_index]
        def prev_log_term = self[:prev_log_term]
        def leader_commit = self[:leader_commit]
        def entries = self[:entries]
      end

      class AppendEntriesResponse < Message
        TYPE = "append_entries_response"
        def success = self[:success]
        def match_index = self[:match_index]
        def conflict_index = self[:conflict_index]
        def conflict_term = self[:conflict_term]
      end

      class InstallSnapshot < Message
        TYPE = "install_snapshot"
        def last_included_index = self[:last_included_index]
        def last_included_term = self[:last_included_term]
        def offset = self[:offset]
        def data = self[:data]
        def done = self[:done]
        def total_bytes = self[:total_bytes]
      end

      class InstallSnapshotResponse < Message
        TYPE = "install_snapshot_response"
        def success = self[:success]
        def last_included_index = self[:last_included_index]
      end

      class ForwardProposal < Message
        TYPE = "forward_proposal"
        def command = self[:command]
      end

      class ForwardProposalResponse < Message
        TYPE = "forward_proposal_response"
        def accepted = self[:accepted]
        def index = self[:index]
        def entry_term = self[:entry_term]
        def leader_id = self[:leader_id]
      end

      class ReadIndex < Message
        TYPE = "read_index"
      end

      class ReadIndexResponse < Message
        TYPE = "read_index_response"
        def read_index = self[:read_index]
        def accepted = self[:accepted]
      end

      class TimeoutNow < Message
        TYPE = "timeout_now"
      end

      CLASSES = {
        "request_vote" => RequestVote,
        "request_vote_response" => RequestVoteResponse,
        "append_entries" => AppendEntries,
        "append_entries_response" => AppendEntriesResponse,
        "install_snapshot" => InstallSnapshot,
        "install_snapshot_response" => InstallSnapshotResponse,
        "pre_vote" => PreVote,
        "pre_vote_response" => PreVoteResponse,
        "forward_proposal" => ForwardProposal,
        "forward_proposal_response" => ForwardProposalResponse,
        "read_index" => ReadIndex,
        "read_index_response" => ReadIndexResponse,
        "timeout_now" => TimeoutNow
      }.freeze

      REQUIRED_FIELDS = {
        "request_vote" => %w[last_log_index last_log_term],
        "pre_vote" => %w[last_log_index last_log_term],
        "request_vote_response" => %w[granted],
        "pre_vote_response" => %w[granted],
        "append_entries" => %w[prev_log_index prev_log_term leader_commit entries],
        "append_entries_response" => %w[success match_index conflict_index conflict_term],
        "install_snapshot" => %w[last_included_index last_included_term offset data done total_bytes],
        "install_snapshot_response" => %w[success last_included_index],
        "forward_proposal" => %w[command],
        "forward_proposal_response" => %w[accepted index entry_term leader_id],
        "read_index" => [],
        "read_index_response" => %w[read_index accepted],
        "timeout_now" => []
      }.freeze

      module_function

      def build(type, **fields)
        CLASSES.fetch(type.to_s) { raise ProtocolError, "unknown message type #{type.inspect}" }.new(**fields)
      end

      def from_h(value)
        raise ProtocolError, "message must be an object" unless value.is_a?(Hash)

        type = value["type"]
        klass = CLASSES[type]
        raise ProtocolError, "unknown message type #{type.inspect}" unless klass

        required = %w[cluster_id from to term request_id] + REQUIRED_FIELDS.fetch(type)
        missing = required.reject { |key| value.key?(key) }
        raise ProtocolError, "message #{type} is missing #{missing.join(", ")}" unless missing.empty?
        raise ProtocolError, "message term must be a non-negative integer" unless value["term"].is_a?(Integer) && value["term"] >= 0

        extra = value.keys - required - ["type"]
        raise ProtocolError, "message #{type} has unknown fields #{extra.join(", ")}" unless extra.empty?

        fields = REQUIRED_FIELDS.fetch(type).each_with_object({}) { |key, hash| hash[key.to_sym] = value.fetch(key) }
        validate_fields!(type, fields)
        klass.new(cluster_id: value["cluster_id"], from: value["from"], to: value["to"], term: value["term"],
                  request_id: value["request_id"], **fields)
      end

      def decode(bytes, max_bytes: Canonical::DEFAULT_MAX_BYTES)
        from_h(Canonical.decode(bytes, max_bytes: max_bytes))
      end

      def validate_fields!(type, fields)
        case type
        when "append_entries"
          entries = fields[:entries]
          raise ProtocolError, "entries must be an array" unless entries.is_a?(Array)

          entries.each { |entry| Log::Entry.from_h(entry) }
          %i[prev_log_index prev_log_term leader_commit].each do |key|
            raise ProtocolError, "#{key} must be a non-negative integer" unless fields[key].is_a?(Integer) && fields[key] >= 0
          end
        when "install_snapshot"
          raise ProtocolError, "snapshot data must be a String" unless fields[:data].is_a?(String)
          %i[last_included_index last_included_term offset total_bytes].each do |key|
            raise ProtocolError, "#{key} must be a non-negative integer" unless fields[key].is_a?(Integer) && fields[key] >= 0
          end
        when "request_vote", "pre_vote"
          %i[last_log_index last_log_term].each do |key|
            raise ProtocolError, "#{key} must be a non-negative integer" unless fields[key].is_a?(Integer) && fields[key] >= 0
          end
        end
      rescue WALCorruption => error
        raise ProtocolError, "invalid log entry in message: #{error.message}"
      end
    end
  end
end
