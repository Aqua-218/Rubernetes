# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # The JSON conversions of a record's FROZEN parts (a Pod object, a
      # container spec, a status snapshot, an event entry), kept between
      # persists: a deeply frozen value cannot change, so its conversion is
      # reused as it is.  Keyed by object identity (compare_by_identity), so
      # no two values ever share an entry; strong references with an LRU
      # bound, because an ObjectSpace::WeakMap drops its values at the next
      # GC (the earlier cache missed almost always).  Mutable parts (a
      # container entry, its status) are converted every time: verifying a
      # cached conversion against them costs as much as converting.
      class ConversionCache
        DEFAULT_LIMIT = 8192

        def initialize(limit: DEFAULT_LIMIT)
          @entries = {}.compare_by_identity
          @limit = Integer(limit)
        end

        def size = @entries.size

        def fetch(value)
          converted = @entries.delete(value)
          return nil if converted.nil?

          @entries[value] = converted
        end

        def store(value, converted)
          @entries.delete(value)
          @entries[value] = converted
          @entries.shift while @entries.size > @limit
          converted
        end
      end
    end
  end
end
