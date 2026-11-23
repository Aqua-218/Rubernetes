# frozen_string_literal: true

require_relative "dns_wire"
require_relative "nat64_prefix"

module Rubernetes
  module Network
    module DNS
      # DNS64 for names resolved by a recursive upstream. Internal records
      # stay authoritative and use their original address families.
      class DNS64
        MAX_CNAME_DEPTH = 8
        DEFAULT_MAX_TTL = 600

        def initialize(prefix)
          @prefix = Nat64Prefix.new(prefix)
        end

        def synthesize(query, reply)
          question = query.questions.first
          return reply unless question.type == Wire::TYPE_AAAA && question.klass == Wire::CLASS_IN
          return reply if query.cd || query.edns&.flags.to_i.anybits?(Wire::EDNS_FLAG_DO)
          return reply if reply.tc || reply.rcode != Wire::RCODE_NOERROR || reply.edns&.extended_rcode.to_i.positive?
          return reply if reply.answers.any? { |record| record.type == Wire::TYPE_AAAA }

          ipv4_question = question.dup
          ipv4_question.type = Wire::TYPE_A
          ipv4_query = query.dup
          ipv4_query.questions = [ipv4_question]
          ipv4_reply = yield ipv4_query
          return ipv4_reply if ipv4_reply.tc || ipv4_reply.rcode != Wire::RCODE_NOERROR || ipv4_reply.edns&.extended_rcode.to_i.positive?

          aliases, addresses = address_chain(question.name, ipv4_reply.answers)
          soa = reply.authority.find { |record| record.type == Wire::TYPE_SOA && record.klass == Wire::CLASS_IN }
          ttl_limit = soa ? [soa.ttl, soa.rdata.fetch("minimum")].min : DEFAULT_MAX_TTL
          synthesized = addresses.filter_map do |record|
            address = @prefix.embed(record.rdata)
            next unless address

            Wire::Record.new(name: record.name, type: Wire::TYPE_AAAA, klass: Wire::CLASS_IN,
                             ttl: [record.ttl, ttl_limit].min, rdata: address)
          end
          return reply if synthesized.empty?

          Wire::Message.new(id: reply.id, qr: true, rd: reply.rd, ra: ipv4_reply.ra,
                            questions: reply.questions, answers: aliases + synthesized)
        end

        private

        def address_chain(name, answers)
          # Only synthesize from an address RRset belonging to the original
          # question or a reachable alias. Additional data is never used.
          records = answers.select { |record| record.klass == Wire::CLASS_IN }
          by_owner = records.group_by(&:name)
          dnames = records.select { |record| record.type == Wire::TYPE_DNAME }
          aliases = []
          seen = [name]
          (MAX_CNAME_DEPTH + 1).times do
            rrset = by_owner.fetch(name, [])
            addresses = rrset.select { |record| record.type == Wire::TYPE_A }
            return [aliases.uniq, addresses] unless addresses.empty?

            cname = rrset.find { |record| record.type == Wire::TYPE_CNAME }
            break if cname.nil? || seen.include?(cname.rdata)

            covering_dname = dnames.find do |record|
              suffix = ".#{record.name}"
              name.end_with?(suffix) && cname.rdata == "#{name.delete_suffix(suffix)}.#{record.rdata}"
            end
            aliases << covering_dname if covering_dname
            aliases << cname
            name = cname.rdata
            seen << name
          end
          [[], []]
        end
      end
    end
  end
end
