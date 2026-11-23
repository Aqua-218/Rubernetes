#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require_relative "lean_oracle"
require_relative "../../lib/rubernetes/consensus"
require_relative "../../lib/rubernetes/runtime"
require_relative "../../lib/rubernetes/runtime/microvm/framing"

module FramingOracle
  SOURCE = File.expand_path("../../verification/lean/BoundedFraming.lean", __dir__)
  TRANSPORT = Rubernetes::Consensus::Transport
  MICROVM = Rubernetes::Runtime::MicroVM
  SEED = 20_260_918

  # A complete header followed by immediate EOF. Capture the requested
  # payload size without creating the payload the peer announced.
  class HeaderStream
    attr_reader :requests

    def initialize(header)
      @header = header
      @requests = []
    end

    def read(count)
      @requests << count
      result = @header
      @header = nil
      result
    end

    def readpartial(count)
      read(count) || raise(EOFError)
    end
  end

  module_function

  def run(lean: LeanOracle.executable, seed: SEED)
    random = Random.new(seed)
    cases = [0, 1, 257, TRANSPORT::MAX_FRAME_BYTES].flat_map { |bound| headers("raft", bound, random) }
    cases.concat(headers("vsock", MICROVM::Framing::MAX_FRAME_BYTES, random))
    reference = LeanOracle.run(SOURCE, cases, lean: lean)

    mismatches = cases.each_with_index.filter_map do |input, index|
      actual = payload_request(input)
      expected = reference.fetch(index)
      {"input" => input, "ruby" => actual, "lean" => expected} unless actual == expected
    end
    {"passed" => mismatches.empty?, "seed" => seed, "cases" => cases.length,
     "source_sha256" => Digest::SHA256.file(SOURCE).hexdigest, "mismatches" => mismatches}
  end

  def headers(protocol, bound, random)
    lengths = [0, 1, bound, bound + 1, 0xffff_ffff]
    lengths.concat(Array.new(24) { random.rand(0..((bound * 2) + 1)) })
    lengths.uniq.map { |length| {"protocol" => protocol, "bound" => bound, "length" => length} }
  end

  def payload_request(input)
    length = input.fetch("length")
    if input.fetch("protocol") == "raft"
      raft_payload_request(length, input.fetch("bound"))
    else
      vsock_payload_request(length)
    end
  end

  def raft_payload_request(length, bound)
    io = HeaderStream.new([length, TRANSPORT::TYPE_MESSAGE].pack("NC"))
    result = TRANSPORT::Framing.read(io, max_bytes: bound)
    result.last.bytesize
  rescue Rubernetes::Consensus::FrameTooLarge, Rubernetes::Consensus::ProtocolError
    io.requests[1]
  end

  def vsock_payload_request(length)
    io = HeaderStream.new([length].pack("N"))
    MICROVM::Framing.read_frame(io)
  rescue MICROVM::FramingError
    io.requests[1]
  end
end

if $PROGRAM_NAME == __FILE__
  report = FramingOracle.run
  puts JSON.pretty_generate(report)
  exit(report.fetch("passed") ? 0 : 1)
end
