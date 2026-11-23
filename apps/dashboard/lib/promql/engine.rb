# frozen_string_literal: true

require_relative "parser"
require_relative "functions"
require_relative "../tsdb/store"

module Promql
  class EvalError < StandardError; end

  # Query engine over a Tsdb::Store with Prometheus semantics:
  # 5-minute lookback for instant selectors, left-open range windows,
  # stale markers ending a series, extrapolated rate/increase, one-to-one
  # and many-to-one vector matching, metric names dropped by arithmetic and
  # by every function except the handful that keep them.
  class Engine
    LOOKBACK_MS = 5 * 60 * 1000
    DEFAULT_STEP_MS = 60 * 1000
    MAX_SAMPLES = 50_000_000

    # One series in a result.  `metric` is the label set (metric name in
    # __name__ when present).  Instant results carry `point`; matrices `points`.
    Series = Struct.new(:metric, :point, :points, keyword_init: true) do
      # The grouping key: `by`/`on` keep only the listed labels (which may
      # name __name__), `without`/`ignoring` drop the listed labels and the
      # metric name, plain one-to-one matching ignores the metric name.
      def signature(labels = nil, without: false, on: false)
        source = if on
                   metric.select { |k, _| labels.include?(k) }
                 elsif without
                   metric.reject { |k, _| labels.include?(k) || k == "__name__" }
                 else
                   metric.reject { |k, _| k == "__name__" }
                 end
        source.sort.map { |k, v| "#{k}\u0000#{v}" }.join("\u0001")
      end
    end

    Result = Struct.new(:type, :value, :warnings, :infos, keyword_init: true) do
      def to_api
        result = case type
                 when :scalar then api_point(value)
                 when :string then [value[0] / 1000.0, value[1]]
                 when :vector
                   value.map do |series|
                     key = histogram?(series.point) ? "histogram" : "value"
                     {"metric" => series.metric, key => api_point(series.point)}
                   end
                 when :matrix
                   value.map do |series|
                     histograms, floats = series.points.partition { |point| histogram?(point) }
                     entry = {"metric" => series.metric}
                     entry["values"] = floats.map { |point| api_point(point) } unless floats.empty?
                     entry["histograms"] = histograms.map { |point| api_point(point) } unless histograms.empty?
                     entry
                   end
                 end
        {"resultType" => type.to_s, "result" => result}
      end

      private

      def histogram?(point) = point[1].is_a?(Prom::NativeHistogram)

      def api_point(point)
        t, v = point
        [t / 1000.0, histogram?(point) ? v.to_api : Engine.format_value(v)]
      end
    end

    def self.format_value(value)
      return value.to_s if value.is_a?(Prom::NativeHistogram)

      Prom::NativeHistogram.number_text(value)
    end

    attr_reader :store, :lookback_ms, :default_step_ms

    def initialize(store, lookback_ms: LOOKBACK_MS, default_step_ms: DEFAULT_STEP_MS, now: nil)
      @store = store
      @lookback_ms = lookback_ms
      @default_step_ms = default_step_ms
      @now = now
    end

    # Instant query.  `time_ms` defaults to now.  Returns a Result.
    def query(expression, time_ms = nil)
      time_ms ||= now_ms
      ast = expression.is_a?(String) ? Promql::Parser.parse(expression) : expression
      context = Context.new(self, start_ms: time_ms, end_ms: time_ms, step_ms: 0)
      value = eval_node(ast, time_ms, context)
      wrap_instant(value, time_ms).tap do |result|
        result.warnings = context.warnings.keys
        result.infos = context.infos.keys
      end
    end

    # Range query: evaluates the expression at every step and returns a
    # matrix (or a matrix of scalar values, as Prometheus does).
    def query_range(expression, start_ms, end_ms, step_ms)
      raise EvalError, "step must be positive" unless step_ms.positive?
      raise EvalError, "end must not be before start" if end_ms < start_ms
      raise EvalError, "exceeded maximum resolution of 11,000 points per timeseries" if (end_ms - start_ms) / step_ms > 11_000

      ast = expression.is_a?(String) ? Promql::Parser.parse(expression) : expression
      context = Context.new(self, start_ms: start_ms, end_ms: end_ms, step_ms: step_ms)
      raise EvalError, "invalid expression type #{ast.type} for range query, must be Scalar or instant Vector" unless %i[scalar
                                                                                                                         vector].include?(ast.type)

      series_by_sig = {}
      order = []
      t = start_ms
      while t <= end_ms
        value = eval_node(ast, t, context)
        case value
        when Numeric
          entry = (series_by_sig[""] ||= begin
            order << ""
            Series.new(metric: {}, points: [])
          end)
          entry.points << [t, value.to_f]
        when Array
          value.each do |series|
            key = series.metric.sort.to_s
            entry = series_by_sig[key]
            if entry.nil?
              entry = Series.new(metric: series.metric, points: [])
              series_by_sig[key] = entry
              order << key
            end
            entry.points << series.point
          end
        end
        t += step_ms
      end
      Result.new(type: :matrix, value: order.map { |key| series_by_sig[key] },
                 warnings: context.warnings.keys, infos: context.infos.keys)
    end

    # Series metadata for /api/v1/series.
    def series(matcher_sets, start_ms, end_ms)
      matcher_sets.flat_map do |matchers|
        store.query(matchers.map { |m| to_store_matcher(m) }, start_ms, end_ms).map { |s, _| s.labels }
      end.uniq
    end

    def now_ms
      @now ? @now.call : (Time.now.to_f * 1000).to_i
    end

    # -------------------------------------------------------------- eval

    class Context
      attr_reader :engine, :start_ms, :end_ms, :step_ms, :warnings, :infos
      attr_accessor :samples_loaded

      def initialize(engine, start_ms:, end_ms:, step_ms:)
        @engine = engine
        @start_ms = start_ms
        @end_ms = end_ms
        @step_ms = step_ms
        @cache = {}
        @warnings = {}
        @infos = {}
        @samples_loaded = 0
      end

      # Fetch and memoise the raw series for a selector over the whole query
      # window plus the widest lookback that any evaluation will need.
      def selector_data(selector, extra_ms)
        key = [selector.matchers.map(&:to_a), extra_ms, selector.offset_ms, selector.at]
        @cache[key] ||= begin
          min_t, max_t = engine.send(:window_for, selector, self, extra_ms)
          matchers = selector.matchers.map { |m| engine.send(:to_store_matcher, m) }
          data = engine.store.query(matchers, min_t, max_t).map { |series, points| [series.labels, points] }
          @samples_loaded += data.sum do |_, points|
            points.sum do |_, value|
              value.is_a?(Prom::NativeHistogram) ? 1 + ((value.negative.size + value.positive.size + value.custom_bounds.size) / 4) : 1
            end
          end
          raise EvalError, "query processing would load too many samples into memory" if @samples_loaded > MAX_SAMPLES

          data
        end
      end
    end

    private

    def wrap_instant(value, time_ms)
      case value
      when String then Result.new(type: :string, value: [time_ms, value])
      when Numeric then Result.new(type: :scalar, value: [time_ms, value.to_f])
      when MatrixValue then Result.new(type: :matrix, value: value.series)
      else Result.new(type: :vector, value: value)
      end
    end

    MatrixValue = Struct.new(:series)

    def to_store_matcher(matcher)
      Tsdb::Store::Matcher.new(name: matcher.name, op: matcher.op, value: matcher.value)
    end

    def eval_time_for(node, t, context)
      time = t
      case node.at
      when Integer then time = node.at
      when :start then time = context.start_ms
      when :end then time = context.end_ms
      end
      time - node.offset_ms.to_i
    end

    def window_for(selector, context, extra_ms)
      case selector.at
      when Integer
        base_min = base_max = selector.at
      when :start
        base_min = base_max = context.start_ms
      when :end
        base_min = base_max = context.end_ms
      else
        base_min = context.start_ms
        base_max = context.end_ms
      end
      offset = selector.offset_ms.to_i
      [base_min - offset - extra_ms, base_max - offset]
    end

    def eval_node(node, t, context)
      case node
      when AST::NumberLiteral then node.value
      when AST::StringLiteral then node.value
      when AST::ParenExpr then eval_node(node.expr, t, context)
      when AST::UnaryExpr
        value = eval_node(node.expr, t, context)
        value.is_a?(Numeric) ? -value : value.map { |s| Series.new(metric: drop_name(s.metric), point: [s.point[0], -s.point[1]]) }
      when AST::VectorSelector then eval_vector_selector(node, t, context)
      when AST::MatrixSelector then eval_matrix_selector(node, t, context)
      when AST::SubqueryExpr then eval_subquery(node, t, context)
      when AST::BinaryExpr then eval_binary(node, t, context)
      when AST::AggregateExpr then eval_aggregate(node, t, context)
      when AST::Call then eval_call(node, t, context)
      else raise EvalError, "cannot evaluate #{node.class}"
      end
    end

    def eval_vector_selector(node, t, context)
      time = eval_time_for(node, t, context)
      data = context.selector_data(node, @lookback_ms)
      data.filter_map do |labels, points|
        point = last_point_before(points, time)
        next if point.nil?

        Series.new(metric: labels, point: [t, point[1]])
      end
    end

    # The most recent sample at or before `time` within the lookback window,
    # unless a stale marker ended the series.
    def last_point_before(points, time)
      index = bsearch_last(points, time)
      return nil if index.nil?

      point = points[index]
      return nil if point[0] < time - @lookback_ms
      return nil if Tsdb::Store.stale_marker?(point[1])

      point
    end

    def bsearch_last(points, time)
      low = 0
      high = points.length - 1
      result = nil
      while low <= high
        mid = (low + high) / 2
        if points[mid][0] <= time
          result = mid
          low = mid + 1
        else
          high = mid - 1
        end
      end
      result
    end

    def eval_matrix_selector(node, t, context)
      selector = node.selector
      time = eval_time_for(selector, t, context)
      data = context.selector_data(selector, node.range_ms)
      MatrixValue.new(data.filter_map do |labels, points|
        window = points.select { |pt| pt[0] > time - node.range_ms && pt[0] <= time && !Tsdb::Store.stale_marker?(pt[1]) }
        next if window.empty?

        Series.new(metric: labels, points: window)
      end)
    end

    def eval_subquery(node, t, context)
      time = eval_time_for(node, t, context)
      step = node.step_ms || @default_step_ms
      start = time - node.range_ms
      # Align to the step, as Prometheus does for subqueries.
      first = start - (start % step) + step
      first -= step while first > start + step
      first = start + step if first <= start
      inner = Context.new(self, start_ms: first, end_ms: time, step_ms: step)
      by_sig = {}
      order = []
      ts = first
      while ts <= time
        value = eval_node(node.expr, ts, inner)
        Array(value).each do |series|
          next unless series.is_a?(Series)

          key = series.metric.sort.to_s
          entry = by_sig[key]
          if entry.nil?
            entry = Series.new(metric: series.metric, points: [])
            by_sig[key] = entry
            order << key
          end
          entry.points << [ts, series.point[1]]
        end
        ts += step
      end
      context.warnings.merge!(inner.warnings)
      context.infos.merge!(inner.infos)
      MatrixValue.new(order.map { |key| by_sig[key] })
    end

    # ---------------------------------------------------------- binary ops

    ARITHMETIC = {
      "+" => ->(a, b) { a + b },
      "-" => ->(a, b) { a - b },
      "*" => ->(a, b) { a * b },
      "/" => lambda { |a, b|
        if b.zero?
          if a.zero? || a.nan?
            Float::NAN
          else
            (a.positive? ? Float::INFINITY : -Float::INFINITY)
          end
        else
          a / b
        end
      },
      "%" => nil, # handled by go_mod
      "^" => ->(a, b) { a**b },
      "atan2" => ->(a, b) { Math.atan2(a, b) }
    }.freeze
    COMPARISON = {
      "==" => ->(a, b) { a == b },
      "!=" => ->(a, b) { a != b },
      "<" => ->(a, b) { a < b },
      ">" => ->(a, b) { a > b },
      "<=" => ->(a, b) { a <= b },
      ">=" => ->(a, b) { a >= b }
    }.freeze

    def scalar_op(op, a, b)
      if ARITHMETIC.key?(op)
        return go_mod(a, b) if op == "%"

        ARITHMETIC[op].call(a, b)
      else
        COMPARISON[op].call(a, b) ? 1.0 : 0.0
      end
    end

    # Go's math.Mod: result has the sign of the dividend.
    def go_mod(a, b)
      return Float::NAN if b.zero? || a.infinite? || b.nan? || a.nan?
      return a if b.infinite?

      a - (b * (a / b).truncate)
    end

    def eval_binary(node, t, context)
      lhs = eval_node(node.lhs, t, context)
      rhs = eval_node(node.rhs, t, context)
      op = node.op
      return set_operation(op, lhs, rhs, node.matching) if %w[and or unless].include?(op)
      return scalar_op(op, lhs.to_f, rhs.to_f) if lhs.is_a?(Numeric) && rhs.is_a?(Numeric)

      if lhs.is_a?(Numeric) || rhs.is_a?(Numeric)
        vector = lhs.is_a?(Numeric) ? rhs : lhs
        scalar = (lhs.is_a?(Numeric) ? lhs : rhs).to_f
        swap = lhs.is_a?(Numeric)
        return vector.filter_map do |series|
          a = swap ? scalar : series.point[1]
          b = swap ? series.point[1] : scalar
          value = sample_op(op, a, b, context)
          next if value.nil?

          if COMPARISON.key?(op)
            keep = value == 1.0
            if node.return_bool
              Series.new(metric: drop_name(series.metric), point: [t, keep ? 1.0 : 0.0])
            elsif keep
              Series.new(metric: series.metric, point: series.point)
            end
          else
            Series.new(metric: drop_name(series.metric), point: [t, value])
          end
        end
      end
      vector_vector(op, lhs, rhs, node, t, context)
    end

    def sample_op(op, left, right, context)
      left_hist = left.is_a?(Prom::NativeHistogram)
      right_hist = right.is_a?(Prom::NativeHistogram)
      return scalar_op(op, left, right) unless left_hist || right_hist

      if left_hist && right_hist
        case op
        when "+", "-" then histogram_arithmetic(op, left, right, context)
        when "==", "!=" then COMPARISON.fetch(op).call(left, right) ? 1.0 : 0.0
        end
      elsif op == "*"
        left_hist ? left * right : right * left
      elsif op == "/" && left_hist
        left / right
      end
    rescue Prom::NativeHistogram::IncompatibleSchema
      context.warnings["PromQL warning: incompatible bucket layout encountered for binary operator #{op.inspect}"] = true
      nil
    end

    def histogram_arithmetic(operator, left, right, context, operation: operator == "+" ? "addition" : "subtraction")
      if left.custom? && right.custom? && left.custom_bounds != right.custom_bounds
        context.infos["PromQL info: mismatched custom buckets were reconciled during #{operation}"] = true
      end
      left.public_send(operator, right)
    end

    def sum_histograms(samples, context)
      samples.reduce { |a, b| histogram_arithmetic("+", a, b, context, operation: "aggregation") }
    end

    def match_signature(series, matching)
      series.signature(matching.labels, without: !matching.on, on: matching.on)
    end

    def vector_vector(op, lhs, rhs, node, t, context)
      matching = node.matching || AST::VectorMatching.new
      # Right side is the "one" side for many_to_one; swap for one_to_many.
      if matching.card == :one_to_many
        lhs, rhs = rhs, lhs
        swapped = true
      else
        swapped = false
      end
      right_by_sig = {}
      rhs.each do |series|
        sig = match_signature(series, matching)
        if right_by_sig.key?(sig) && matching.card == :one_to_one
          raise EvalError,
                "found duplicate series for the match group #{sig_labels(series, matching)} on the right hand-side of the operation"
        end
        raise EvalError, "found duplicate series for the match group on the right hand-side of the operation" if right_by_sig.key?(sig)

        right_by_sig[sig] = series
      end
      seen_left = {}
      result = []
      lhs.each do |series|
        sig = match_signature(series, matching)
        other = right_by_sig[sig]
        next unless other

        a = swapped ? other.point[1] : series.point[1]
        b = swapped ? series.point[1] : other.point[1]
        value = sample_op(op, a, b, context)
        next if value.nil?

        if COMPARISON.key?(op)
          keep = value == 1.0
          value = swapped ? other.point[1] : series.point[1] unless node.return_bool
          next if !keep && !node.return_bool
        end
        metric = result_metric(series, other, matching, op, node.return_bool)
        key = metric.sort.to_s
        if matching.card == :one_to_one
          raise EvalError, "multiple matches for labels: many-to-one matching must be explicit (group_left/group_right)" if seen_left.key?(sig)

          seen_left[sig] = true
        elsif seen_left.key?(key)
          raise EvalError, "multiple matches for labels: grouping labels must ensure unique matches"
        else
          seen_left[key] = true
        end
        result << Series.new(metric: metric, point: [t, value])
      end
      result
    end

    def sig_labels(series, matching)
      series.metric.select { |k, _| matching.on ? matching.labels.include?(k) : !matching.labels.include?(k) && k != "__name__" }
    end

    def result_metric(left, right, matching, op, bool)
      metric = left.metric.dup
      metric.delete("__name__") if ARITHMETIC.key?(op) || bool
      if matching.card == :one_to_one
        if matching.on
          metric = metric.select { |k, _| matching.labels.include?(k) || k == "__name__" }
        else
          matching.labels.each { |label| metric.delete(label) }
        end
      else
        matching.include.each do |label|
          if right.metric.key?(label)
            metric[label] = right.metric[label]
          else
            metric.delete(label)
          end
        end
      end
      metric
    end

    def set_operation(op, lhs, rhs, matching)
      matching ||= AST::VectorMatching.new(:many_to_many)
      right_sigs = rhs.to_h { |s| [match_signature(s, matching), s] }
      case op
      when "and"
        lhs.select { |s| right_sigs.key?(match_signature(s, matching)) }
      when "unless"
        lhs.reject { |s| right_sigs.key?(match_signature(s, matching)) }
      when "or"
        left_sigs = lhs.to_h { |s| [match_signature(s, matching), true] }
        lhs + rhs.reject { |s| left_sigs.key?(match_signature(s, matching)) }
      end
    end

    # --------------------------------------------------------- aggregations

    def eval_aggregate(node, t, context)
      vector = eval_node(node.expr, t, context)
      param = node.param ? eval_node(node.param, t, context) : nil
      groups = {}
      order = []
      vector.each do |series|
        key = series.signature(node.grouping, without: node.without, on: !node.without)
        unless groups.key?(key)
          metric = if node.without
                     series.metric.reject { |k, _| node.grouping.include?(k) || k == "__name__" }
                   else
                     series.metric.select { |k, _| node.grouping.include?(k) }
                   end
          groups[key] = {metric: metric, members: []}
          order << key
        end
        groups[key][:members] << series
      end
      result = []
      order.each do |key|
        group = groups[key]
        all_values = group[:members].map { |s| s.point[1] }
        values = all_values.grep(Numeric)
        case node.op
        when "sum", "avg"
          if values.empty?
            begin
              total = sum_histograms(all_values, context)
            rescue Prom::NativeHistogram::IncompatibleSchema
              warn_mixed_histogram_schemas(context, group[:metric])
              next
            end
          elsif values.length == all_values.length
            total = values.sum
          else
            warn_mixed(context, group[:metric])
            next
          end
          total /= all_values.length if node.op == "avg"
          result << Series.new(metric: group[:metric], point: [t, total])
        when "min", "max"
          next if values.empty?

          value = values.reject(&:nan?).public_send(node.op) || Float::NAN
          result << Series.new(metric: group[:metric], point: [t, value])
        when "count" then result << Series.new(metric: group[:metric], point: [t, all_values.length.to_f])
        when "group" then result << Series.new(metric: group[:metric], point: [t, 1.0])
        when "stddev", "stdvar", "quantile"
          next if values.empty?

          value = case node.op
                  when "stddev" then Math.sqrt(variance(values))
                  when "stdvar" then variance(values)
                  when "quantile" then quantile(param.to_f, values)
                  end
          result << Series.new(metric: group[:metric], point: [t, value])
        when "count_values"
          label = param.to_s
          counts = Hash.new(0)
          all_values.each { |v| counts[Engine.format_value(v)] += 1 }
          counts.each do |value, count|
            result << Series.new(metric: group[:metric].merge(label => value), point: [t, count.to_f])
          end
        when "topk", "bottomk"
          k = param.to_f
          next if k.nan? || k < 1

          k = k.to_i
          sorted = float_series(group[:members]).reject { |s| s.point[1].nan? }
          sorted = node.op == "topk" ? sorted.sort_by { |s| -s.point[1] } : sorted.sort_by { |s| s.point[1] }
          sorted.first(k).each { |s| result << Series.new(metric: s.metric, point: s.point) }
        when "limitk"
          k = param.to_i
          group[:members].first([k, 0].max).each { |s| result << Series.new(metric: s.metric, point: s.point) }
        when "limit_ratio"
          ratio = param.to_f.clamp(-1.0, 1.0)
          count = (group[:members].length * ratio.abs).round
          picked = ratio >= 0 ? group[:members].first(count) : group[:members].last(count)
          picked.each { |s| result << Series.new(metric: s.metric, point: s.point) }
        else raise EvalError, "unknown aggregation #{node.op}"
        end
      end
      result
    end

    def variance(values)
      return Float::NAN if values.empty?

      mean = values.sum / values.length
      values.sum { |v| (v - mean)**2 } / values.length
    end

    # Prometheus quantile: linear interpolation over the sorted values.
    def quantile(q, values)
      return Float::NAN if values.empty? || q.nan?
      return -Float::INFINITY if q.negative?
      return Float::INFINITY if q > 1

      sorted = values.sort
      n = sorted.length.to_f
      rank = q * (n - 1)
      lower = rank.floor
      upper = [lower + 1, n - 1].min.to_i
      weight = rank - lower
      (sorted[lower] * (1 - weight)) + (sorted[upper] * weight)
    end

    # ------------------------------------------------------------- functions

    def eval_call(node, t, context)
      name = node.func
      args = node.args
      case name
      when "time" then t / 1000.0
      when "pi" then Math::PI
      when "vector"
        [Series.new(metric: {}, point: [t, eval_node(args[0], t, context).to_f])]
      when "scalar"
        floats = float_series(eval_node(args[0], t, context))
        floats.length == 1 ? floats[0].point[1] : Float::NAN
      when "timestamp"
        eval_node(args[0], t, context).map { |s| Series.new(metric: drop_name(s.metric), point: [t, timestamp_of(s, args[0], t, context)]) }
      when "absent"
        vector = eval_node(args[0], t, context)
        vector.empty? ? [Series.new(metric: absent_labels(args[0]), point: [t, 1.0])] : []
      when "absent_over_time"
        matrix = eval_node(args[0], t, context)
        if matrix.series.empty?
          [Series.new(metric: absent_labels(args[0].is_a?(AST::MatrixSelector) ? args[0].selector : nil),
                      point: [t, 1.0])]
        else
          []
        end
      when "rate", "increase", "delta", "irate", "idelta", "deriv", "changes", "resets",
           "avg_over_time", "sum_over_time", "min_over_time", "max_over_time", "count_over_time", "last_over_time",
           "stddev_over_time", "stdvar_over_time", "present_over_time", "mad_over_time"
        matrix = eval_node(args[0], t, context)
        range_ms = range_of(args[0])
        window_end = range_end(args[0], t, context)
        matrix.series.filter_map do |series|
          value = range_function(name, series, window_end, range_ms, context)
          next if value.nil?

          metric = name == "last_over_time" ? series.metric : drop_name(series.metric)
          Series.new(metric: metric, point: [t, value])
        end
      when "quantile_over_time"
        q = eval_node(args[0], t, context).to_f
        matrix = eval_node(args[1], t, context)
        matrix.series.filter_map do |s|
          values = float_points(s.points).map(&:last)
          Series.new(metric: drop_name(s.metric), point: [t, quantile(q, values)]) unless values.empty?
        end
      when "predict_linear"
        matrix = eval_node(args[0], t, context)
        seconds = eval_node(args[1], t, context).to_f
        matrix.series.filter_map do |s|
          points = float_points(s.points)
          next if points.length < 2

          slope, intercept = linear_regression(points, t)
          Series.new(metric: drop_name(s.metric), point: [t, (slope * seconds) + intercept])
        end
      when "holt_winters", "double_exponential_smoothing"
        matrix = eval_node(args[0], t, context)
        sf = eval_node(args[1], t, context).to_f
        tf = eval_node(args[2], t, context).to_f
        raise EvalError, "invalid smoothing factor. Expected: 0 < sf < 1" unless sf.positive? && sf < 1
        raise EvalError, "invalid trend factor. Expected: 0 < tf < 1" unless tf.positive? && tf < 1

        matrix.series.filter_map do |s|
          points = float_points(s.points)
          next if points.length < 2

          Series.new(metric: drop_name(s.metric), point: [t, holt_winters(points.map(&:last), sf, tf)])
        end
      when *HISTOGRAM_FIELDS.keys
        field = HISTOGRAM_FIELDS.fetch(name)
        eval_node(args[0], t, context).filter_map do |s|
          value = s.point[1]
          Series.new(metric: drop_name(s.metric), point: [t, value.public_send(field)]) if value.is_a?(Prom::NativeHistogram)
        end
      when "histogram_quantile"
        q = eval_node(args[0], t, context).to_f
        histogram_function(eval_node(args[1], t, context), t, context, ->(h) { h.quantile(q) }, ->(b) { bucket_quantile(q, b) })
      when "histogram_fraction"
        lower = eval_node(args[0], t, context).to_f
        upper = eval_node(args[1], t, context).to_f
        histogram_function(eval_node(args[2], t, context), t, context,
                           ->(h) { h.fraction(lower, upper) }, ->(b) { bucket_fraction(lower, upper, b) })
      when "label_replace"
        vector = eval_node(args[0], t, context)
        dst, replacement, src, regex = args[1..].map { |a| eval_node(a, t, context).to_s }
        raise EvalError, "invalid destination label name in label_replace(): #{dst}" unless dst.match?(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)

        pattern = Regexp.new("\\A(?:#{regex})\\z")
        vector.map do |s|
          value = s.metric.fetch(src, "")
          match = pattern.match(value)
          metric = s.metric.dup
          if match
            expanded = replacement.gsub(/\$(\d+|\{\d+\}|\{[a-zA-Z_]\w*\})/) do
              ref = Regexp.last_match(1).delete("{}")
              if ref.match?(/\A\d+\z/)
                match[ref.to_i].to_s
              else
                (match.names.include?(ref) ? match[ref].to_s : "")
              end
            end
            expanded.empty? ? metric.delete(dst) : metric[dst] = expanded
          end
          Series.new(metric: metric, point: s.point)
        end
      when "label_join"
        vector = eval_node(args[0], t, context)
        dst = eval_node(args[1], t, context).to_s
        separator = eval_node(args[2], t, context).to_s
        sources = args[3..].map { |a| eval_node(a, t, context).to_s }
        raise EvalError, "invalid destination label name in label_join(): #{dst}" unless dst.match?(/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)

        vector.map do |s|
          value = sources.map { |src| s.metric.fetch(src, "") }.join(separator)
          metric = s.metric.dup
          value.empty? ? metric.delete(dst) : metric[dst] = value
          Series.new(metric: metric, point: s.point)
        end
      when "sort" then float_series(eval_node(args[0], t, context)).sort_by { |s| sort_key(s.point[1]) }
      when "sort_desc" then float_series(eval_node(args[0], t, context)).sort_by { |s| sort_key(s.point[1]) }.reverse
      when "sort_by_label", "sort_by_label_desc"
        vector = eval_node(args[0], t, context)
        labels = args[1..].map { |a| eval_node(a, t, context).to_s }
        sorted = vector.sort_by { |s| labels.map { |l| s.metric.fetch(l, "") } }
        name == "sort_by_label" ? sorted : sorted.reverse
      when "round"
        vector = eval_node(args[0], t, context)
        nearest = args[1] ? eval_node(args[1], t, context).to_f : 1.0
        float_series(vector).map { |s| Series.new(metric: drop_name(s.metric), point: [t, round_to(s.point[1], nearest)]) }
      when "clamp"
        vector = eval_node(args[0], t, context)
        lo = eval_node(args[1], t, context).to_f
        hi = eval_node(args[2], t, context).to_f
        return [] if lo > hi

        float_series(vector).map { |s| Series.new(metric: drop_name(s.metric), point: [t, s.point[1].clamp(lo, hi)]) }
      when "clamp_min"
        lo = eval_node(args[1], t, context).to_f
        float_series(eval_node(args[0], t, context)).map { |s| Series.new(metric: drop_name(s.metric), point: [t, [s.point[1], lo].max]) }
      when "clamp_max"
        hi = eval_node(args[1], t, context).to_f
        float_series(eval_node(args[0], t, context)).map { |s| Series.new(metric: drop_name(s.metric), point: [t, [s.point[1], hi].min]) }
      when *Functions::TIME_FUNCTIONS
        vector = args.empty? ? [Series.new(metric: {}, point: [t, t / 1000.0])] : eval_node(args[0], t, context)
        float_series(vector).map { |s| Series.new(metric: drop_name(s.metric), point: [t, time_function(name, s.point[1])]) }
      else
        math = MATH_FUNCTIONS[name]
        raise EvalError, "unsupported function #{name}" unless math

        float_series(eval_node(args[0], t, context)).map { |s| Series.new(metric: drop_name(s.metric), point: [t, math.call(s.point[1])]) }
      end
    end

    HISTOGRAM_FIELDS = {
      "histogram_avg" => :average, "histogram_count" => :count, "histogram_stddev" => :standard_deviation,
      "histogram_stdvar" => :variance, "histogram_sum" => :sum
    }.freeze

    MATH_FUNCTIONS = {
      "abs" => lambda(&:abs),
      "ceil" => ->(v) { v.finite? ? v.ceil.to_f : v },
      "floor" => ->(v) { v.finite? ? v.floor.to_f : v },
      "exp" => ->(v) { Math.exp(v) },
      "sqrt" => ->(v) { v.negative? ? Float::NAN : Math.sqrt(v) },
      "ln" => lambda { |v|
        if v.negative?
          Float::NAN
        else
          (v.zero? ? -Float::INFINITY : Math.log(v))
        end
      },
      "log2" => lambda { |v|
        if v.negative?
          Float::NAN
        else
          (v.zero? ? -Float::INFINITY : Math.log2(v))
        end
      },
      "log10" => lambda { |v|
        if v.negative?
          Float::NAN
        else
          (v.zero? ? -Float::INFINITY : Math.log10(v))
        end
      },
      "sgn" => lambda { |v|
        if v.nan?
          v
        else
          (if v.positive?
             1.0
           else
             (v.negative? ? -1.0 : 0.0)
           end)
        end
      },
      "deg" => ->(v) { v * 180 / Math::PI },
      "rad" => ->(v) { v * Math::PI / 180 },
      "sin" => ->(v) { Math.sin(v) }, "cos" => ->(v) { Math.cos(v) }, "tan" => ->(v) { Math.tan(v) },
      "asin" => ->(v) { v.abs > 1 ? Float::NAN : Math.asin(v) }, "acos" => ->(v) { v.abs > 1 ? Float::NAN : Math.acos(v) },
      "atan" => ->(v) { Math.atan(v) },
      "sinh" => ->(v) { Math.sinh(v) }, "cosh" => ->(v) { Math.cosh(v) }, "tanh" => ->(v) { Math.tanh(v) },
      "asinh" => ->(v) { Math.asinh(v) }, "acosh" => ->(v) { v < 1 ? Float::NAN : Math.acosh(v) },
      "atanh" => lambda { |v|
        if v.abs > 1
          Float::NAN
        else
          (if v.abs == 1
             v.positive? ? Float::INFINITY : -Float::INFINITY
           else
             Math.atanh(v)
           end)
        end
      }
    }.freeze

    def float_series(vector) = vector.select { |s| s.point[1].is_a?(Numeric) }
    def float_points(points) = points.select { |_, v| v.is_a?(Numeric) }

    def warn_mixed(context, labels)
      context.warnings["PromQL warning: encountered a mix of histograms and floats for #{labels.fetch("__name__", labels)}"] = true
    end

    def warn_mixed_histogram_schemas(context, labels)
      metric = labels.fetch("__name__", "")
      context.warnings["PromQL warning: vector contains a mix of histograms with exponential and custom buckets schemas for metric name #{metric.inspect}"] =
        true
    end

    def sort_key(value)
      value.nan? ? -Float::INFINITY : value
    end

    def round_to(value, nearest)
      return value unless value.finite?

      to_nearest_inverse = 1.0 / nearest
      ((value * to_nearest_inverse) + 0.5).floor / to_nearest_inverse
    end

    def drop_name(metric)
      metric.key?("__name__") ? metric.reject { |k, _| k == "__name__" } : metric
    end

    def range_of(node)
      case node
      when AST::MatrixSelector then node.range_ms
      when AST::SubqueryExpr then node.range_ms
      when AST::ParenExpr then range_of(node.expr)
      else raise EvalError, "range function needs a range vector"
      end
    end

    def range_end(node, t, context)
      case node
      when AST::MatrixSelector then eval_time_for(node.selector, t, context)
      when AST::SubqueryExpr then eval_time_for(node, t, context)
      when AST::ParenExpr then range_end(node.expr, t, context)
      end
    end

    def timestamp_of(series, node, t, context)
      selector = node.is_a?(AST::ParenExpr) ? node.expr : node
      return t / 1000.0 unless selector.is_a?(AST::VectorSelector)

      data = context.selector_data(selector, @lookback_ms)
      time = eval_time_for(selector, t, context)
      _, points = data.find { |labels, _| labels == series.metric }
      point = points && last_point_before(points, time)
      point ? point[0] / 1000.0 : t / 1000.0
    end

    def absent_labels(selector)
      return {} unless selector.is_a?(AST::VectorSelector)

      selector.matchers.each_with_object({}) do |m, labels|
        labels[m.name] = m.value if m.op == "=" && m.name != "__name__"
      end
    end

    def time_function(name, seconds)
      time = Time.at(seconds).utc
      case name
      when "hour" then time.hour.to_f
      when "minute" then time.min.to_f
      when "month" then time.month.to_f
      when "year" then time.year.to_f
      when "day_of_month" then time.day.to_f
      when "day_of_week" then time.wday.to_f
      when "day_of_year" then time.yday.to_f
      when "days_in_month" then Date.new(time.year, time.month, -1).day.to_f
      end
    end

    # ----------------------------------------------------- range functions

    def range_function(name, series, t, range_ms, context)
      points = series.points
      floats = float_points(points)
      case name
      when "count_over_time" then return points.length.to_f
      when "last_over_time" then return points.last&.last
      when "present_over_time" then return 1.0
      when "changes", "resets"
        return points.each_cons(2).count { |a, b| sample_changed?(name, a[1], b[1]) }.to_f
      when "rate", "increase", "delta", "avg_over_time", "sum_over_time"
        if !floats.empty? && floats.length != points.length
          warn_mixed(context, series.metric)
          return nil
        end
      when "irate", "idelta"
        points = points.last(2)
        if points.length == 2 && points[0][1].class != points[1][1].class
          warn_mixed(context, series.metric)
          return nil
        end
      else
        points = floats
      end
      return nil if points.empty?

      values = points.map(&:last)
      case name
      when "rate" then extrapolated_rate(points, t, range_ms, counter: true, rate: true, context: context)
      when "increase" then extrapolated_rate(points, t, range_ms, counter: true, rate: false, context: context)
      when "delta" then extrapolated_rate(points, t, range_ms, counter: false, rate: false, context: context)
      when "irate", "idelta"
        return nil if points.length < 2

        last = points[-1]
        prev = points[-2]
        result = if name == "irate" && sample_changed?("resets", prev[1], last[1])
                   last[1]
                 elsif last[1].is_a?(Prom::NativeHistogram)
                   histogram_arithmetic("-", last[1], prev[1], context)
                 else
                   last[1] - prev[1]
                 end
        result = result.as_gauge if result.is_a?(Prom::NativeHistogram)
        return nil if last[0] == prev[0]

        name == "irate" ? result / ((last[0] - prev[0]) / 1000.0) : result
      when "deriv"
        return nil if points.length < 2

        linear_regression(points, points[0][0]).first
      when "avg_over_time", "sum_over_time"
        total = values.first.is_a?(Prom::NativeHistogram) ? sum_histograms(values, context) : values.sum
        name == "avg_over_time" ? total / values.length : total
      when "min_over_time" then values.empty? ? nil : values.reject(&:nan?).min || Float::NAN
      when "max_over_time" then values.empty? ? nil : values.reject(&:nan?).max || Float::NAN
      when "stddev_over_time" then values.empty? ? nil : Math.sqrt(variance(values))
      when "stdvar_over_time" then values.empty? ? nil : variance(values)
      when "mad_over_time"
        return nil if values.empty?

        median = quantile(0.5, values)
        quantile(0.5, values.map { |v| (v - median).abs })
      end
    rescue Prom::NativeHistogram::IncompatibleSchema
      warn_mixed_histogram_schemas(context, series.metric)
      nil
    end

    def sample_changed?(name, previous, current)
      return true if previous.class != current.class

      if current.is_a?(Prom::NativeHistogram)
        return current.reset_from?(previous) if name == "resets"

        current != previous
      elsif name == "resets"
        current < previous
      else
        current != previous && !(current.nan? && previous.nan?)
      end
    end

    # promql/functions.go extrapolatedRate: the increase over the window is
    # extrapolated to the window's edges, but by at most half a sample
    # interval, and for counters never below zero.
    def extrapolated_rate(points, t, range_ms, counter:, rate:, context:)
      return nil if points.length < 2

      range_start = t - range_ms
      range_end = t
      first = points.first
      last = points.last
      histogram = first[1].is_a?(Prom::NativeHistogram)
      # A reset between the first two samples makes the first histogram's
      # bucket layout irrelevant to the result.
      initial = first[1]
      first_reset = histogram && counter && points[1][1].reset_from?(initial)
      if histogram
        initial = points[1][1].empty if first_reset
        raise Prom::NativeHistogram::IncompatibleSchema if counter && points.drop(1).any? { |_, sample| sample.custom? != initial.custom? }

        result = histogram_arithmetic("-", last[1], initial, context)
      else
        result = last[1] - initial
      end
      if counter
        points.each_cons(2).with_index do |((_, previous), (_, value)), index|
          next if first_reset && index.zero?

          next unless sample_changed?("resets", previous, value)

          result = histogram ? histogram_arithmetic("+", result, previous, context) : result + previous
        end
      end
      duration_to_start = (first[0] - range_start) / 1000.0
      duration_to_end = (range_end - last[0]) / 1000.0
      sampled_interval = (last[0] - first[0]) / 1000.0
      average_interval = sampled_interval / (points.length - 1)
      extrapolation_threshold = average_interval * 1.1
      extrapolate_to_interval = sampled_interval
      duration_to_start = average_interval / 2 if duration_to_start >= extrapolation_threshold
      initial_count = histogram ? first[1].count : initial
      result_count = histogram ? result.count : result
      if counter && result_count.positive? && initial_count >= 0
        duration_to_zero = sampled_interval * (initial_count / result_count)
        duration_to_start = duration_to_zero if duration_to_zero < duration_to_start
      end
      extrapolate_to_interval += duration_to_start
      duration_to_end = average_interval / 2 if duration_to_end >= extrapolation_threshold
      extrapolate_to_interval += duration_to_end
      factor = extrapolate_to_interval / sampled_interval
      factor /= (range_ms / 1000.0) if rate
      result * factor
    end

    def linear_regression(points, intercept_time)
      n = 0.0
      sum_x = sum_y = sum_xy = sum_x2 = 0.0
      points.each do |ts, value|
        x = (ts - intercept_time) / 1000.0
        n += 1
        sum_x += x
        sum_y += value
        sum_xy += x * value
        sum_x2 += x * x
      end
      cov = sum_xy - (sum_x * sum_y / n)
      var = sum_x2 - (sum_x * sum_x / n)
      slope = var.zero? ? 0.0 : cov / var
      intercept = (sum_y / n) - (slope * sum_x / n)
      [slope, intercept]
    end

    def holt_winters(values, sf, tf)
      s0 = values[0]
      s1 = values[1]
      b = s1 - s0
      values[1..].each_with_index do |x, i|
        next if i.zero?

        s_prev = s1
        s1 = (sf * x) + ((1 - sf) * (s_prev + b))
        b = (tf * (s1 - s_prev)) + ((1 - tf) * b)
      end
      s1
    end

    # Classic histogram buckets: interpolate within the bucket containing
    # the quantile, as promql/quantile.go bucketQuantile does.
    def histogram_function(vector, t, context, native, classic)
      histograms, floats = vector.partition { |series| series.point[1].is_a?(Prom::NativeHistogram) }
      groups = {}
      floats.each do |series|
        le = series.metric["le"]
        next if le.nil?

        upper = parse_le(le)
        next if upper.nil?

        metric = series.metric.reject { |k, _| k == "le" }
        groups[metric] ||= []
        groups[metric] << [upper, series.point[1]]
      end
      results = histograms.filter_map do |series|
        equivalent = series.metric.merge("__name__" => "#{series.metric["__name__"]}_bucket")
        if groups.delete(equivalent)
          context.warnings["PromQL warning: encountered a mix of classic and native histograms for #{series.metric["__name__"]}"] = true
          next
        end

        Series.new(metric: drop_name(series.metric), point: [t, native.call(series.point[1])])
      end
      groups.each { |metric, buckets| results << Series.new(metric: drop_name(metric), point: [t, classic.call(buckets)]) }
      results
    end

    def parse_le(text)
      case text
      when "+Inf" then Float::INFINITY
      when "-Inf" then -Float::INFINITY
      else
        value = Float(text)
        value unless value.nan?
      end
    rescue ArgumentError
      nil
    end

    def bucket_quantile(q, buckets)
      return Float::NAN if q.nan?
      return -Float::INFINITY if q.negative?
      return Float::INFINITY if q > 1

      buckets = normalize_buckets(buckets)
      return Float::NAN if buckets.length < 2 || buckets.last[0] != Float::INFINITY

      observations = buckets.last[1]
      return Float::NAN if observations.zero?

      rank = q * observations
      index = buckets.index { |_, count| count >= rank } || (buckets.length - 1)
      return buckets[-2][0] if index == buckets.length - 1
      return buckets[0][0] if index.zero? && buckets[0][0] <= 0

      lower_bound = index.zero? ? 0.0 : buckets[index - 1][0]
      upper_bound = buckets[index][0]
      count_before = index.zero? ? 0.0 : buckets[index - 1][1]
      count = buckets[index][1] - count_before
      rank -= count_before
      return upper_bound if count.zero?

      lower_bound + ((upper_bound - lower_bound) * (rank / count))
    end

    def bucket_fraction(lower, upper, buckets)
      return Float::NAN if lower.nan? || upper.nan?

      buckets = normalize_buckets(buckets)
      return Float::NAN unless buckets.last[0] == Float::INFINITY

      count = buckets.last[1]
      return Float::NAN if count.zero?
      return 0.0 if lower >= upper

      ranks = [lower, upper].map do |boundary|
        previous_bound = -Float::INFINITY
        previous_count = 0.0
        rank = count
        buckets.each do |bound, running|
          if boundary < bound
            previous_bound = 0.0 if previous_bound.infinite? && bound.positive?
            rank = if boundary <= previous_bound || bound.infinite?
                     previous_count
                   elsif previous_bound.infinite?
                     running
                   else
                     previous_count + ((running - previous_count) * (boundary - previous_bound) / (bound - previous_bound))
                   end
            break
          end
          previous_bound = bound
          previous_count = running
        end
        rank
      end
      (ranks[1] - ranks[0]) / count
    end

    def normalize_buckets(buckets)
      counts = Hash.new(0.0)
      buckets.each { |upper, count| counts[upper] += count }
      running = 0.0
      counts.sort.map do |upper, count|
        running = count if count > running
        [upper, running]
      end
    end
  end
end
