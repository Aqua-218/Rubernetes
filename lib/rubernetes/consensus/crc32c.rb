# frozen_string_literal: true

module Rubernetes
  module Consensus
    # CRC-32C (Castagnoli) used by WAL format 1; the polynomial is the same
    # one used by SCTP, iSCSI and ext4.  Pure Ruby, table driven, a byte at a
    # time -- about 0.1 us per byte, which is why format 2 moved to zlib's
    # CRC-32 for new files.  This stays to read and extend format 1 files.
    module CRC32C
      POLYNOMIAL = 0x82F63B78
      TABLE = Array.new(256) do |index|
        crc = index
        8.times { crc = crc.odd? ? (crc >> 1) ^ POLYNOMIAL : crc >> 1 }
        crc
      end.freeze

      module_function

      def checksum(bytes, initial = 0)
        crc = initial ^ 0xFFFFFFFF
        bytes.each_byte { |byte| crc = TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8) }
        crc ^ 0xFFFFFFFF
      end
    end
  end
end
