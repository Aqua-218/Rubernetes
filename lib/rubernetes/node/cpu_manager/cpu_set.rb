# frozen_string_literal: true

module Rubernetes
  module Node
    module CPUManager
      # k8s.io/utils/cpuset.CPUSet: an immutable set of CPU ids, printed and
      # parsed in the Linux list format ("0-3,8,10-11").
      class CPUSet
        include Enumerable

        class ParseError < ArgumentError; end

        def self.[](*ids) = new(ids.flatten)

        def self.empty = EMPTY

        # cpuset.Parse.
        def self.parse(text)
          text = text.to_s.strip
          return EMPTY if text.empty?

          ids = []
          text.split(",").each do |range|
            bounds = range.split("-", -1)
            case bounds.length
            when 1
              ids << integer(bounds[0], text)
            when 2
              first = integer(bounds[0], text)
              last = integer(bounds[1], text)
              raise ParseError, "invalid range #{range.dump} (#{first} > #{last})" if first > last

              ids.concat((first..last).to_a)
            else
              raise ParseError, "invalid cpuset #{text.dump}"
            end
          end
          new(ids)
        end

        def self.integer(value, text)
          Integer(value, 10)
        rescue ArgumentError, TypeError
          raise ParseError, "invalid cpuset #{text.dump}"
        end
        private_class_method :integer

        def initialize(ids = [])
          @ids = ids.map { |id| Integer(id) }.uniq.sort.freeze
          freeze
        end

        def list = @ids
        alias to_a list
        def each(&) = @ids.each(&)
        def size = @ids.length
        def empty? = @ids.empty?
        def include?(id) = @ids.bsearch { |value| value >= id } == id
        alias contains? include?

        def union(*others) = CPUSet.new(others.reduce(@ids) { |ids, other| ids + other.to_a })
        def intersection(other) = CPUSet.new(@ids & other.to_a)
        def difference(other) = CPUSet.new(@ids - other.to_a)
        def subset_of?(other) = (@ids - other.to_a).empty?
        alias | union
        alias & intersection
        alias - difference

        def ==(other) = other.is_a?(CPUSet) && other.list == @ids
        alias eql? ==
        def hash = @ids.hash

        # cpuset.CPUSet.String: consecutive ids collapse into ranges.
        def to_s
          ranges = []
          @ids.each do |id|
            if ranges.last && ranges.last[1] == id - 1
              ranges.last[1] = id
            else
              ranges << [id, id]
            end
          end
          ranges.map { |first, last| first == last ? first.to_s : "#{first}-#{last}" }.join(",")
        end

        def inspect = "#<CPUSet #{self}>"

        EMPTY = new([])
      end
    end
  end
end
