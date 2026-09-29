// Expression browser: queries /api/v1/query and /api/v1/query_range and
// renders a table or an SVG line chart.  No chart library: the whole thing
// is a few hundred lines so the dashboard needs nothing from a CDN.

const RANGES = ["5m", "15m", "1h", "6h", "1d", "7d"];
const COLORS = ["#4cc2ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#ff7b72", "#79c0ff", "#56d364", "#e3b341", "#ffa657", "#d2a8ff", "#a5d6ff"];

function durationSeconds(text) {
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)?$/.exec(text.trim());
  if (!m) return null;
  const v = parseFloat(m[1]);
  return { ms: v / 1000, s: v, m: v * 60, h: v * 3600, d: v * 86400, w: v * 604800, y: v * 31536000 }[m[2] || "s"];
}

function formatValue(v) {
  const n = parseFloat(v);
  if (!isFinite(n)) return v;
  if (Math.abs(n) >= 1e6 || (Math.abs(n) < 1e-3 && n !== 0)) return n.toExponential(3);
  return Number.isInteger(n) ? String(n) : n.toPrecision(5).replace(/\.?0+$/, "");
}

function formatTime(seconds, spanSeconds) {
  const d = new Date(seconds * 1000);
  const pad = (x) => String(x).padStart(2, "0");
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (spanSeconds > 2 * 86400) return `${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${hm}`;
  if (spanSeconds > 3600) return hm;
  return `${hm}:${pad(d.getSeconds())}`;
}

function seriesName(metric) {
  const name = metric.__name__ || "";
  const labels = Object.entries(metric).filter(([k]) => k !== "__name__").map(([k, v]) => `${k}="${v}"`).join(", ");
  return labels ? `${name}{${labels}}` : name || "{}";
}

export class GraphPanel {
  constructor(root) {
    this.root = root;
    this.form = root.querySelector("form.graph-form");
    this.expr = root.querySelector("textarea[name=expr]");
    this.rangeInput = root.querySelector("input[name=range]");
    this.stepInput = root.querySelector("input[name=step]");
    this.endInput = root.querySelector("input[name=end]");
    this.output = root.querySelector(".graph-output");
    this.status = root.querySelector(".graph-status");
    this.tab = root.dataset.tab || "graph";
    this.hidden = new Set();
    this.form.addEventListener("submit", (e) => { e.preventDefault(); this.run(); });
    this.expr.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); this.run(); } });
    root.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => { this.tab = b.dataset.tab; this.updateTabs(); this.run(); }));
    root.querySelectorAll(".range-picker button").forEach((b) => b.addEventListener("click", () => { this.rangeInput.value = b.dataset.range; this.run(); }));
    root.querySelector(".refresh")?.addEventListener("change", (e) => this.setAutoRefresh(e.target.value));
    this.updateTabs();
    if (this.expr.value.trim()) this.run();
  }

  updateTabs() {
    this.root.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === this.tab));
    this.root.querySelector(".range-controls").style.display = this.tab === "graph" ? "" : "none";
    this.root.querySelectorAll(".range-picker button").forEach((b) => b.classList.toggle("active", b.dataset.range === this.rangeInput.value));
  }

  setAutoRefresh(value) {
    clearInterval(this.timer);
    const seconds = durationSeconds(value || "");
    if (seconds) this.timer = setInterval(() => this.run(), seconds * 1000);
  }

  async run() {
    const expr = this.expr.value.trim();
    if (!expr) return;
    const params = new URLSearchParams(window.location.search);
    params.set("g0_expr", expr); params.set("g0_tab", this.tab); params.set("g0_range_input", this.rangeInput.value);
    history.replaceState(null, "", `${window.location.pathname}?${params}`);
    this.status.textContent = "Loading…";
    const started = performance.now();
    try {
      const data = this.tab === "graph" ? await this.queryRange(expr) : await this.queryInstant(expr);
      const elapsed = ((performance.now() - started) / 1000).toFixed(3);
      if (data.status !== "success") {
        this.output.innerHTML = `<div class="graph-error">${escapeHtml(data.errorType || "error")}: ${escapeHtml(data.error || "")}</div>`;
        this.status.textContent = "";
        return;
      }
      const count = Array.isArray(data.data.result) ? data.data.result.length : 1;
      this.status.textContent = `Load time: ${elapsed}s · Result series: ${count}${data.warnings ? " · " + data.warnings.join("; ") : ""}`;
      if (this.tab === "graph") this.renderGraph(data.data); else this.renderTable(data.data);
    } catch (error) {
      this.output.innerHTML = `<div class="graph-error">${escapeHtml(String(error))}</div>`;
      this.status.textContent = "";
    }
  }

  async queryInstant(expr) {
    const params = new URLSearchParams({ query: expr });
    if (this.endInput.value) params.set("time", this.endInput.value);
    const response = await fetch(`/api/v1/query?${params}`, { headers: { Accept: "application/json" } });
    return response.json();
  }

  async queryRange(expr) {
    const range = durationSeconds(this.rangeInput.value) || 3600;
    const end = this.endInput.value ? Date.parse(this.endInput.value) / 1000 : Date.now() / 1000;
    const start = end - range;
    const width = this.output.clientWidth || 1000;
    let step = this.stepInput.value ? durationSeconds(this.stepInput.value) : null;
    if (!step) step = Math.max(Math.floor(range / Math.max(width / 3, 50)), 1);
    const params = new URLSearchParams({ query: expr, start: start.toFixed(3), end: end.toFixed(3), step: String(step) });
    const response = await fetch(`/api/v1/query_range?${params}`, { headers: { Accept: "application/json" } });
    return response.json();
  }

  renderTable(data) {
    let rows = [];
    if (data.resultType === "scalar" || data.resultType === "string") {
      rows = [`<tr><td class="metric-cell">scalar</td><td class="num">${escapeHtml(String(data.result[1]))}</td></tr>`];
    } else if (data.resultType === "vector") {
      rows = data.result.map((s) => `<tr><td class="metric-cell">${escapeHtml(seriesName(s.metric))}</td><td class="num">${escapeHtml(formatValue(s.value[1]))}</td></tr>`);
    } else {
      rows = data.result.map((s) => `<tr><td class="metric-cell">${escapeHtml(seriesName(s.metric))}</td><td class="mono">${s.values.map((v) => `${formatValue(v[1])} @${v[0]}`).join("<br>")}</td></tr>`);
    }
    if (rows.length === 0) rows = ['<tr><td colspan="2" class="muted">Empty query result</td></tr>'];
    this.output.innerHTML = `<table><thead><tr><th>Element</th><th class="num">Value</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
  }

  renderGraph(data) {
    if (data.resultType !== "matrix") { this.renderTable(data); return; }
    const series = data.result.map((s, i) => ({ name: seriesName(s.metric), color: COLORS[i % COLORS.length], points: s.values.map(([t, v]) => [t, parseFloat(v)]) }));
    if (series.length === 0) { this.output.innerHTML = '<div class="muted">Empty query result</div>'; return; }
    const width = Math.max(this.output.clientWidth || 1000, 400);
    const height = 360;
    const pad = { l: 64, r: 16, t: 12, b: 28 };
    let minT = Infinity, maxT = -Infinity, minV = Infinity, maxV = -Infinity;
    series.forEach((s) => s.points.forEach(([t, v]) => {
      if (t < minT) minT = t; if (t > maxT) maxT = t;
      if (isFinite(v)) { if (v < minV) minV = v; if (v > maxV) maxV = v; }
    }));
    if (!isFinite(minV)) { minV = 0; maxV = 1; }
    if (minV === maxV) { minV -= 1; maxV += 1; }
    if (minV > 0 && minV < maxV * 0.2) minV = 0;
    const x = (t) => pad.l + ((t - minT) / Math.max(maxT - minT, 1)) * (width - pad.l - pad.r);
    const y = (v) => pad.t + (1 - (v - minV) / (maxV - minV)) * (height - pad.t - pad.b);
    const ticks = 5;
    let svg = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">`;
    for (let i = 0; i <= ticks; i++) {
      const v = minV + ((maxV - minV) * i) / ticks;
      svg += `<line x1="${pad.l}" x2="${width - pad.r}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)" stroke-width="1"/>`;
      svg += `<text x="${pad.l - 6}" y="${y(v) + 4}" text-anchor="end" fill="var(--muted)" font-size="11">${formatValue(v)}</text>`;
    }
    const span = maxT - minT;
    for (let i = 0; i <= 6; i++) {
      const t = minT + (span * i) / 6;
      svg += `<text x="${x(t)}" y="${height - 8}" text-anchor="middle" fill="var(--muted)" font-size="11">${formatTime(t, span)}</text>`;
    }
    series.forEach((s, index) => {
      if (this.hidden.has(s.name)) return;
      let d = "";
      let pen = false;
      s.points.forEach(([t, v]) => {
        if (!isFinite(v)) { pen = false; return; }
        d += `${pen ? "L" : "M"}${x(t).toFixed(1)},${y(v).toFixed(1)} `;
        pen = true;
      });
      svg += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="1.6" data-index="${index}"/>`;
    });
    svg += `<line class="cursor" x1="0" x2="0" y1="${pad.t}" y2="${height - pad.b}" stroke="var(--muted)" stroke-dasharray="3,3" style="display:none"/>`;
    svg += "</svg>";
    const legend = series.map((s) => `<span class="item ${this.hidden.has(s.name) ? "dim" : ""}" data-name="${escapeHtml(s.name)}"><span class="swatch" style="background:${s.color}"></span>${escapeHtml(s.name)}</span>`).join("");
    this.output.innerHTML = `<div class="graph-panel">${svg}<div class="legend">${legend}</div><div class="tooltip"></div></div>`;
    this.output.querySelectorAll(".legend .item").forEach((el) => el.addEventListener("click", () => {
      const name = el.dataset.name;
      if (this.hidden.has(name)) this.hidden.delete(name); else this.hidden.add(name);
      this.renderGraph(data);
    }));
    const svgEl = this.output.querySelector("svg");
    const tooltip = this.output.querySelector(".tooltip");
    const cursor = svgEl.querySelector(".cursor");
    svgEl.addEventListener("mousemove", (event) => {
      const rect = svgEl.getBoundingClientRect();
      const px = ((event.clientX - rect.left) / rect.width) * width;
      const t = minT + ((px - pad.l) / (width - pad.l - pad.r)) * span;
      cursor.setAttribute("x1", px); cursor.setAttribute("x2", px); cursor.style.display = "";
      const lines = series.filter((s) => !this.hidden.has(s.name)).map((s) => {
        let best = null;
        s.points.forEach((p) => { if (best === null || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p; });
        return best && isFinite(best[1]) ? `<span class="swatch" style="background:${s.color}"></span>${escapeHtml(s.name)}: <b>${formatValue(best[1])}</b>` : null;
      }).filter(Boolean).slice(0, 12);
      tooltip.innerHTML = `<div class="muted">${new Date(t * 1000).toLocaleString()}</div>${lines.join("<br>")}`;
      tooltip.style.display = lines.length ? "block" : "none";
      tooltip.style.left = `${Math.min(event.clientX + 14, window.innerWidth - 540)}px`;
      tooltip.style.top = `${event.clientY + 14}px`;
    });
    svgEl.addEventListener("mouseleave", () => { tooltip.style.display = "none"; cursor.style.display = "none"; });
  }
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

document.addEventListener("turbo:load", () => {
  document.querySelectorAll("[data-graph-panel]").forEach((root) => {
    if (!root.graphPanel) root.graphPanel = new GraphPanel(root);
  });
});

export { RANGES };
