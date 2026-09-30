# frozen_string_literal: true

# RFC 1035 wire codec for the cluster DNS server.
#
# The codec is deliberately allocation-simple and bounds-checked: every read
# validates the remaining length first, name decompression follows at most
# MAX_POINTERS backward pointers, and encoding refuses names or messages that
# would exceed the protocol limits.  Parsing failures raise FormatError so the
# server can answer FORMERR with the client's transaction ID instead of
# guessing at a partially decoded question.
require "ipaddr"

module Rubernetes
  module Network
    module DNS
      module Wire
        class FormatError < StandardError; end

        # RR TYPE values (RFC 1035 §3.2.2, RFC 3596, RFC 2782, RFC 6891).
        TYPE_A = 1
        TYPE_NS = 2
        TYPE_CNAME = 5
        TYPE_SOA = 6
        TYPE_PTR = 12
        TYPE_TXT = 16
        TYPE_AAAA = 28
        TYPE_SRV = 33
        TYPE_OPT = 41
        TYPE_ANY = 255
        TYPE_NAMES = {
          TYPE_A => "A", TYPE_NS => "NS", TYPE_CNAME => "CNAME", TYPE_SOA => "SOA", TYPE_PTR => "PTR",
          TYPE_TXT => "TXT", TYPE_AAAA => "AAAA", TYPE_SRV => "SRV", TYPE_OPT => "OPT", TYPE_ANY => "ANY"
        }.freeze
        TYPE_VALUES = TYPE_NAMES.invert.freeze

        # CLASS values (RFC 1035 §3.2.4).
        CLASS_IN = 1
        CLASS_ANY = 255

        # RCODE values (RFC 1035 §4.1.1).
        RCODE_NOERROR = 0
        RCODE_FORMERR = 1
        RCODE_SERVFAIL = 2
        RCODE_NXDOMAIN = 3
        RCODE_NOTIMP = 4
        RCODE_REFUSED = 5
        RCODE_NAMES = {
          RCODE_NOERROR => "NOERROR", RCODE_FORMERR => "FORMERR", RCODE_SERVFAIL => "SERVFAIL",
          RCODE_NXDOMAIN => "NXDOMAIN", RCODE_NOTIMP => "NOTIMP", RCODE_REFUSED => "REFUSED"
        }.freeze

        OPCODE_QUERY = 0

        # Header flag bits (RFC 1035 §4.1.1).
        FLAG_QR = 0x8000
        FLAG_AA = 0x0400
        FLAG_TC = 0x0200
        FLAG_RD = 0x0100
        FLAG_RA = 0x0080

        HEADER_BYTES = 12
        MAX_NAME_BYTES = 255
        MAX_LABEL_BYTES = 63
        MAX_POINTERS = 64
        CLASSIC_UDP_PAYLOAD = 512
        # RFC 6891 §6.2.5 recommends 1232 as a safe default that avoids IP
        # fragmentation on every common path.
        EDNS_UDP_PAYLOAD = 1232
        MAX_MESSAGE_BYTES = 65_535

        Question = Struct.new(:name, :type, :klass, keyword_init: true) do
          def type_name
            TYPE_NAMES.fetch(type, type.to_s)
          end

          def to_h
            {"name" => name, "type" => type_name, "class" => klass}
          end
        end

        Record = Struct.new(:name, :type, :klass, :ttl, :rdata, keyword_init: true) do
          def type_name
            TYPE_NAMES.fetch(type, type.to_s)
          end

          def to_h
            {"name" => name, "type" => type_name, "class" => klass, "ttl" => ttl, "rdata" => rdata_for_h}
          end

          def rdata_for_h
            case rdata
            when Hash then rdata.transform_keys(&:to_s)
            when String then rdata.encoding == Encoding::BINARY ? rdata.unpack1("H*") : rdata
            else rdata
            end
          end
        end

        # EDNS(0) OPT pseudo-record state (RFC 6891).
        EDNS = Struct.new(:udp_payload, :extended_rcode, :version, :flags, :options, keyword_init: true) do
          def to_h
            {"udp_payload" => udp_payload, "version" => version, "flags" => flags,
             "options" => options.map { |option| {"code" => option.fetch(0), "data" => option.fetch(1).unpack1("H*")} }}
          end
        end

        Message = Struct.new(:id, :qr, :opcode, :aa, :tc, :rd, :ra, :rcode, :questions, :answers, :authority,
                             :additional, :edns, keyword_init: true) do
          def initialize(**attributes)
            defaults = {qr: false, opcode: OPCODE_QUERY, aa: false, tc: false, rd: false, ra: false,
                        rcode: RCODE_NOERROR, questions: [], answers: [], authority: [], additional: [], edns: nil}
            super(**defaults.merge(attributes))
          end

          def rcode_name
            RCODE_NAMES.fetch(rcode, rcode.to_s)
          end

          def to_h
            {"id" => id, "qr" => qr, "opcode" => opcode, "aa" => aa, "tc" => tc, "rd" => rd, "ra" => ra,
             "rcode" => rcode_name, "questions" => questions.map(&:to_h), "answers" => answers.map(&:to_h),
             "authority" => authority.map(&:to_h), "additional" => additional.map(&:to_h),
             "edns" => edns&.to_h}
          end
        end

        module_function

        def type_value(name)
          return Integer(name) if name.is_a?(Integer)

          TYPE_VALUES.fetch(String(name).upcase) { raise ArgumentError, "unsupported DNS record type #{name.inspect}" }
        end

        # Decode one complete message.  A truncated or self-referential name,
        # an RDLENGTH past the end of the buffer, or a section count that the
        # buffer cannot hold raises FormatError; nothing is guessed.
        def decode(bytes)
          buffer = String(bytes).b
          raise FormatError, "DNS message shorter than header" if buffer.bytesize < HEADER_BYTES
          raise FormatError, "DNS message exceeds #{MAX_MESSAGE_BYTES} bytes" if buffer.bytesize > MAX_MESSAGE_BYTES

          id, flags, qdcount, ancount, nscount, arcount = buffer.unpack("n6")
          message = Message.new(
            id: id, qr: flags.anybits?(FLAG_QR), opcode: (flags >> 11) & 0x0f, aa: flags.anybits?(FLAG_AA),
            tc: flags.anybits?(FLAG_TC), rd: flags.anybits?(FLAG_RD), ra: flags.anybits?(FLAG_RA), rcode: flags & 0x0f
          )
          offset = HEADER_BYTES
          qdcount.times do
            name, offset = decode_name(buffer, offset)
            raise FormatError, "truncated question" if offset + 4 > buffer.bytesize

            type, klass = buffer.byteslice(offset, 4).unpack("n2")
            offset += 4
            message.questions << Question.new(name: name, type: type, klass: klass)
          end
          {answers: ancount, authority: nscount, additional: arcount}.each do |section, count|
            count.times do
              record, offset = decode_record(buffer, offset)
              if record.type == TYPE_OPT
                raise FormatError, "duplicate OPT record" if message.edns
                raise FormatError, "OPT record outside the additional section" unless section == :additional

                message.edns = record.rdata
                next
              end
              message.public_send(section) << record
            end
          end
          message
        end

        def decode_name(buffer, offset, _depth = 0)
          labels = []
          pointers = 0
          cursor = offset
          next_offset = nil
          total = 0
          loop do
            raise FormatError, "truncated name" if cursor >= buffer.bytesize

            length = buffer.getbyte(cursor)
            if length.allbits?(0xc0)
              raise FormatError, "truncated compression pointer" if cursor + 1 >= buffer.bytesize

              pointer = ((length & 0x3f) << 8) | buffer.getbyte(cursor + 1)
              # Only backward pointers are legal; a forward or self pointer
              # is how a hostile packet builds an infinite decompression loop.
              raise FormatError, "forward compression pointer" if pointer >= cursor

              pointers += 1
              raise FormatError, "compression pointer chain too long" if pointers > MAX_POINTERS

              next_offset ||= cursor + 2
              cursor = pointer
              next
            end
            raise FormatError, "unsupported label type" unless length.nobits?(0xc0)

            if length.zero?
              next_offset ||= cursor + 1
              break
            end
            raise FormatError, "label exceeds #{MAX_LABEL_BYTES} bytes" if length > MAX_LABEL_BYTES
            raise FormatError, "truncated label" if cursor + 1 + length > buffer.bytesize

            total += length + 1
            raise FormatError, "name exceeds #{MAX_NAME_BYTES} bytes" if total > MAX_NAME_BYTES

            labels << buffer.byteslice(cursor + 1, length)
            cursor += 1 + length
          end
          name = labels.map { |label| label.b.downcase }.join(".")
          [name, next_offset]
        end

        def decode_record(buffer, offset)
          name, offset = decode_name(buffer, offset)
          raise FormatError, "truncated resource record header" if offset + 10 > buffer.bytesize

          type, klass, ttl, rdlength = buffer.byteslice(offset, 10).unpack("nnNn")
          offset += 10
          raise FormatError, "RDLENGTH past end of message" if offset + rdlength > buffer.bytesize

          rdata_start = offset
          rdata = buffer.byteslice(offset, rdlength)
          offset += rdlength
          parsed = case type
                   when TYPE_A
                     raise FormatError, "A RDATA must be 4 bytes" unless rdlength == 4

                     IPAddr.new_ntoh(rdata).to_s
                   when TYPE_AAAA
                     raise FormatError, "AAAA RDATA must be 16 bytes" unless rdlength == 16

                     IPAddr.new_ntoh(rdata).to_s
                   when TYPE_CNAME, TYPE_PTR, TYPE_NS
                     target, _end = decode_name(buffer, rdata_start)
                     target
                   when TYPE_SRV
                     raise FormatError, "SRV RDATA too short" if rdlength < 7

                     priority, weight, port = rdata.unpack("n3")
                     target, _end = decode_name(buffer, rdata_start + 6)
                     {"priority" => priority, "weight" => weight, "port" => port, "target" => target}
                   when TYPE_SOA
                     mname, cursor = decode_name(buffer, rdata_start)
                     rname, cursor = decode_name(buffer, cursor)
                     raise FormatError, "SOA RDATA too short" if cursor + 20 > rdata_start + rdlength

                     serial, refresh, retry_interval, expire, minimum = buffer.byteslice(cursor, 20).unpack("N5")
                     {"mname" => mname, "rname" => rname, "serial" => serial, "refresh" => refresh,
                      "retry" => retry_interval, "expire" => expire, "minimum" => minimum}
                   when TYPE_TXT
                     strings = []
                     cursor = 0
                     while cursor < rdata.bytesize
                       length = rdata.getbyte(cursor)
                       raise FormatError, "truncated TXT string" if cursor + 1 + length > rdata.bytesize

                       strings << rdata.byteslice(cursor + 1, length)
                       cursor += 1 + length
                     end
                     strings
                   when TYPE_OPT
                     # RFC 6891 §6.1.2: CLASS carries the UDP payload size and
                     # TTL carries extended RCODE, version, and flags.
                     options = []
                     cursor = 0
                     while cursor < rdata.bytesize
                       raise FormatError, "truncated EDNS option" if cursor + 4 > rdata.bytesize

                       code, length = rdata.byteslice(cursor, 4).unpack("n2")
                       raise FormatError, "truncated EDNS option data" if cursor + 4 + length > rdata.bytesize

                       options << [code, rdata.byteslice(cursor + 4, length)]
                       cursor += 4 + length
                     end
                     EDNS.new(udp_payload: klass, extended_rcode: (ttl >> 24) & 0xff, version: (ttl >> 16) & 0xff,
                              flags: ttl & 0xffff, options: options)
                   else
                     rdata
                   end
          [Record.new(name: name, type: type, klass: klass, ttl: ttl, rdata: parsed), offset]
        end

        # Encode a message.  Names are compressed against every earlier owner
        # name and RDATA name.  When `max_size` is given and the message does
        # not fit, records are dropped from the end of the additional,
        # authority, and answer sections in that order and TC is set so the
        # client retries over TCP (RFC 1035 §4.2.1 / RFC 2181 §9).
        def encode(message, max_size: nil)
          limit = max_size && Integer(max_size)
          answers = message.answers.dup
          authority = message.authority.dup
          additional = message.additional.dup
          truncated = message.tc
          loop do
            bytes = encode_once(message, answers, authority, additional, truncated: truncated)
            return bytes if limit.nil? || bytes.bytesize <= limit

            truncated = true
            if additional.any?
              additional.pop
            elsif authority.any?
              authority.pop
            elsif answers.any?
              answers.pop
            else
              # Even the bare header/question does not fit; return it with
              # TC set rather than an unparseable prefix.
              return encode_once(message, [], [], [], truncated: true)
            end
          end
        end

        def encode_once(message, answers, authority, additional, truncated:)
          compression = {}
          buffer = "".b
          flags = 0
          flags |= FLAG_QR if message.qr
          flags |= (Integer(message.opcode) & 0x0f) << 11
          flags |= FLAG_AA if message.aa
          flags |= FLAG_TC if truncated
          flags |= FLAG_RD if message.rd
          flags |= FLAG_RA if message.ra
          flags |= Integer(message.rcode) & 0x0f
          extra = message.edns ? 1 : 0
          buffer << [Integer(message.id) & 0xffff, flags, message.questions.length, answers.length, authority.length,
                     additional.length + extra].pack("n6")
          message.questions.each do |question|
            encode_name(buffer, question.name, compression)
            buffer << [Integer(question.type), Integer(question.klass)].pack("n2")
          end
          (answers + authority + additional).each { |record| encode_record(buffer, record, compression) }
          if message.edns
            edns = message.edns
            buffer << "\0".b
            ttl = ((Integer(edns.extended_rcode || 0) & 0xff) << 24) | ((Integer(edns.version || 0) & 0xff) << 16) |
                  (Integer(edns.flags || 0) & 0xffff)
            option_bytes = Array(edns.options).map { |code, data| [Integer(code), data.bytesize].pack("n2") + data.b }.join
            buffer << [TYPE_OPT, Integer(edns.udp_payload), ttl, option_bytes.bytesize].pack("nnNn") << option_bytes
          end
          raise FormatError, "DNS message exceeds #{MAX_MESSAGE_BYTES} bytes" if buffer.bytesize > MAX_MESSAGE_BYTES

          buffer
        end

        def encode_record(buffer, record, compression)
          encode_name(buffer, record.name, compression)
          buffer << [Integer(record.type), Integer(record.klass || CLASS_IN), Integer(record.ttl) & 0xffff_ffff].pack("nnN")
          length_offset = buffer.bytesize
          buffer << "\0\0".b
          rdata_start = buffer.bytesize
          rdata = record.rdata
          case record.type
          when TYPE_A
            buffer << IPAddr.new(String(rdata)).hton
          when TYPE_AAAA
            buffer << IPAddr.new(String(rdata)).hton
          when TYPE_CNAME, TYPE_PTR, TYPE_NS
            encode_name(buffer, String(rdata), compression)
          when TYPE_SRV
            hash = rdata.transform_keys(&:to_s)
            buffer << [Integer(hash.fetch("priority")), Integer(hash.fetch("weight")), Integer(hash.fetch("port"))].pack("n3")
            # RFC 2782 forbids compressing the SRV target, and several
            # resolvers reject it; write it uncompressed.
            encode_name(buffer, String(hash.fetch("target")), nil)
          when TYPE_SOA
            hash = rdata.transform_keys(&:to_s)
            encode_name(buffer, String(hash.fetch("mname")), compression)
            encode_name(buffer, String(hash.fetch("rname")), compression)
            buffer << %w[serial refresh retry expire minimum].map { |key| Integer(hash.fetch(key)) & 0xffff_ffff }.pack("N5")
          when TYPE_TXT
            Array(rdata).each do |string|
              text = String(string).b
              raise FormatError, "TXT string exceeds 255 bytes" if text.bytesize > 255

              buffer << [text.bytesize].pack("C") << text
            end
          else
            buffer << String(rdata).b
          end
          rdlength = buffer.bytesize - rdata_start
          raise FormatError, "RDATA exceeds 65535 bytes" if rdlength > 0xffff

          buffer[length_offset, 2] = [rdlength].pack("n")
        end

        def encode_name(buffer, name, compression)
          labels = normalize_name(name).split(".")
          labels.each_index do |index|
            suffix = labels[index..].join(".")
            if compression && (pointer = compression[suffix])
              buffer << [0xc000 | pointer].pack("n")
              return
            end
            # Pointers can only address the first 16 KiB of the message.
            compression[suffix] = buffer.bytesize if compression && buffer.bytesize < 0x3fff
            label = labels[index].b
            buffer << [label.bytesize].pack("C") << label
          end
          buffer << "\0".b
        end

        def normalize_name(value)
          name = String(value).b.downcase.delete_suffix(".")
          return "" if name.empty?

          raise FormatError, "name exceeds #{MAX_NAME_BYTES} bytes" if name.bytesize > MAX_NAME_BYTES - 2

          name.split(".", -1).each do |label|
            raise FormatError, "empty DNS label" if label.empty?
            raise FormatError, "label exceeds #{MAX_LABEL_BYTES} bytes" if label.bytesize > MAX_LABEL_BYTES
          end
          name
        end

        # The transaction ID and first question are the only fields a client
        # can bind a reply to; extract them without a full decode so a
        # malformed packet can still be answered with FORMERR.
        def peek_id(bytes)
          buffer = String(bytes).b
          return nil if buffer.bytesize < 2

          buffer.unpack1("n")
        end
      end
    end
  end
end
