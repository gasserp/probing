"use strict";

const number = new Intl.NumberFormat("en-US");
const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
const percent = new Intl.NumberFormat("en-US", { style: "percent", maximumFractionDigits: 1 });
const regionNames = typeof Intl.DisplayNames === "function" ? new Intl.DisplayNames(["en"], { type: "region" }) : null;
const SVG = "http://www.w3.org/2000/svg";
const HOUR = 3600000;
const DAY = 24 * HOUR;
const RANGES = { "24h": "24h window", "7d": "7d window", "30d": "30d window", all: "All time" };
const RANGE_PHRASE = { "24h": "previous 24h", "7d": "previous 7d", "30d": "previous 30d" };
// Map and heatmap steps: decades of observations.
const LEVELS = [1, 10, 100, 1000, 10000, 100000];

const state = { insights: null, world: null, range: "7d", resizeTimer: 0, width: 0 };

// ---------- helpers ----------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function svg(tag, attributes = {}, parent) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  if (parent) parent.appendChild(node);
  return node;
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function countryName(code) {
  if (!code) return "Unknown";
  try {
    return (regionNames && regionNames.of(code)) || code;
  } catch {
    return code;
  }
}

function flag(code) {
  if (!/^[A-Z]{2}$/.test(code || "")) return "";
  return String.fromCodePoint(...[...code].map((letter) => 127397 + letter.charCodeAt(0)));
}

function share(part, whole) {
  return whole > 0 ? part / whole : 0;
}

function level(value) {
  let result = 0;
  for (let index = 0; index < LEVELS.length; index += 1) if (value >= LEVELS[index]) result = index + 1;
  return result;
}

function niceStep(maximum, ticks) {
  const raw = maximum / Math.max(1, ticks);
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(raw, 1)));
  for (const factor of [1, 2, 2.5, 5, 10]) {
    if (raw <= factor * magnitude) return Math.max(1, factor * magnitude);
  }
  return 10 * magnitude;
}

function formatHour(date) {
  return `${date.toISOString().slice(0, 10)} ${date.toISOString().slice(11, 16)} UTC`;
}

function formatDay(date) {
  return date.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", timeZone: "UTC" });
}

// ---------- tooltip ----------

const tooltip = {
  node: null,
  show(event, title, rows) {
    if (!this.node) this.node = document.getElementById("tooltip");
    const node = this.node;
    node.replaceChildren(el("strong", "", title));
    for (const row of rows) {
      const line = el("div", "row");
      const label = el("span", row.key ? `key ${row.key}` : "", row.label);
      line.append(label, el("span", "", row.value));
      node.appendChild(line);
    }
    node.hidden = false;
    this.move(event);
  },
  move(event) {
    const node = this.node;
    if (!node || node.hidden) return;
    const margin = 14;
    const rect = node.getBoundingClientRect();
    let x = event.clientX + margin;
    let y = event.clientY + margin;
    if (x + rect.width > window.innerWidth - 8) x = event.clientX - rect.width - margin;
    if (y + rect.height > window.innerHeight - 8) y = event.clientY - rect.height - margin;
    node.style.left = `${Math.max(8, x)}px`;
    node.style.top = `${Math.max(8, y)}px`;
  },
  hide() {
    if (this.node) this.node.hidden = true;
  },
};

function bindTooltip(node, content) {
  node.addEventListener("pointerenter", (event) => {
    const [title, rows] = content();
    tooltip.show(event, title, rows);
  });
  node.addEventListener("pointermove", (event) => tooltip.move(event));
  node.addEventListener("pointerleave", () => tooltip.hide());
}

// ---------- data selection ----------

function currentWindow() {
  const windows = state.insights.windows || [];
  return windows.find((item) => item.id === state.range) || windows.find((item) => item.id === "all") || null;
}

function seriesForRange(view) {
  const hourlyRange = state.range === "24h" || state.range === "7d";
  const source = hourlyRange ? state.insights.hourly : state.insights.daily;
  const start = new Date(view.start).getTime();
  const end = new Date(view.end).getTime();
  const floor = hourlyRange ? start : Math.floor(start / DAY) * DAY;
  return {
    hourly: hourlyRange,
    points: (source || []).filter((point) => {
      const time = new Date(point.start).getTime();
      return time >= floor && time < end;
    }),
  };
}

function previousTotal(view) {
  if (!(state.range in RANGE_PHRASE)) return null;
  const start = new Date(view.start).getTime();
  const span = new Date(view.end).getTime() - start;
  const from = start - span;
  const hourly = state.insights.hourly || [];
  const daily = state.insights.daily || [];
  const pool = hourly.length && new Date(hourly[0].start).getTime() <= from ? hourly : daily;
  if (!pool.length || new Date(pool[0].start).getTime() > from) return null;
  return pool.reduce((sum, point) => {
    const time = new Date(point.start).getTime();
    return time >= from && time < start ? sum + Number(point.total || 0) : sum;
  }, 0);
}

// ---------- KPIs ----------

function renderKPIs(view) {
  const versions = view.ip_versions || {};
  const addresses = Number(versions.ipv4_addresses || 0) + Number(versions.ipv6_addresses || 0);
  setText("kpi-total", number.format(view.total));
  const previous = previousTotal(view);
  const totalSub = document.getElementById("kpi-total-sub");
  totalSub.replaceChildren();
  if (previous) {
    const change = (view.total - previous) / previous;
    const arrow = change >= 0 ? "▲" : "▼";
    totalSub.append(el("span", "delta", `${arrow} ${percent.format(Math.abs(change))}`), ` vs ${RANGE_PHRASE[state.range]}`);
  } else {
    totalSub.textContent = `${number.format(Math.round(view.total / Math.max(1, (new Date(view.end) - new Date(view.start)) / HOUR)))} per hour on average`;
  }

  setText("kpi-ips", `${number.format(addresses)}${versions.addresses_exact === false ? "+" : ""}`);
  setText("kpi-ips-sub", `${number.format(versions.ipv4_addresses || 0)} IPv4 · ${number.format(versions.ipv6_addresses || 0)} IPv6`);

  const countries = view.countries || [];
  if (state.insights.geolocation) {
    setText("kpi-countries", number.format(countries.length));
    setText("kpi-countries-sub", countries.length
      ? `${flag(countries[0].code)} ${countryName(countries[0].code)} leads with ${percent.format(share(countries[0].count, view.total))}`
      : "No located sources");
    const networks = view.networks || [];
    setText("kpi-networks", number.format(view.network_count || networks.length));
    setText("kpi-networks-sub", networks.length
      ? `AS${networks[0].asn} carries ${percent.format(share(networks[0].count, view.total))}`
      : "No resolved networks");
  } else {
    setText("kpi-countries", "-");
    setText("kpi-countries-sub", "Geolocation unavailable");
    setText("kpi-networks", "-");
    setText("kpi-networks-sub", "Geolocation unavailable");
  }

  setText("kpi-ssh", percent.format(share(view.ssh, view.total)));
  setText("kpi-ssh-sub", `${compact.format(view.ssh)} SSH · ${compact.format(view.http)} HTTP probes`);
  const bar = document.getElementById("kpi-vector-bar");
  bar.replaceChildren();
  for (const [key, value] of [["ssh", view.ssh], ["http", view.http]]) {
    if (!value) continue;
    const segment = el("span");
    segment.style.flex = `${value} ${value} 0%`;
    segment.style.background = `var(--series-${key})`;
    bar.appendChild(segment);
  }

  const deny = state.insights.deny_list || {};
  setText("kpi-deny", number.format(deny.recent || 0));
  setText("kpi-deny-sub", `72h recent list · ${number.format(deny.persistent || 0)} on the 30-day persistent list`);
}

// ---------- ranked lists ----------

function renderRanked(id, rows, emptyText = "No accepted values") {
  const list = document.getElementById(id);
  list.replaceChildren();
  if (!rows.length) {
    list.appendChild(el("li", "empty-row", emptyText));
    return [];
  }
  const maximum = Math.max(...rows.map((row) => row.count));
  return rows.map((row) => {
    const item = el("li");
    const label = el("div", "label");
    if (row.flag) label.appendChild(el("span", "flag", row.flag));
    label.appendChild(document.createTextNode(row.label));
    if (row.tag) label.appendChild(el("span", "tag", row.tag));
    if (row.meta) label.appendChild(el("span", "meta", row.meta));
    item.append(label, el("span", "value", number.format(row.count)));
    const bar = el("span", "share");
    bar.style.setProperty("--share", `${(row.count / maximum) * 100}%`);
    bar.setAttribute("aria-hidden", "true");
    item.appendChild(bar);
    if (row.tooltip) bindTooltip(item, row.tooltip);
    list.appendChild(item);
    return item;
  });
}

function renderLists(view) {
  const geo = Boolean(state.insights.geolocation);
  const total = view.total;
  const countryItems = renderRanked("countries", (view.countries || []).slice(0, 12).map((item) => ({
    label: countryName(item.code),
    flag: flag(item.code),
    count: item.count,
    meta: `${percent.format(share(item.count, total))} · ${number.format(item.ips)} ${item.ips === 1 ? "address" : "addresses"}`,
    code: item.code,
  })), geo ? "No located sources in this window" : "Geolocation unavailable");
  countryItems.forEach((node, index) => {
    const code = view.countries[index].code;
    node.addEventListener("pointerenter", () => highlightCountry(code, true));
    node.addEventListener("pointerleave", () => highlightCountry(code, false));
  });

  renderRanked("networks", (view.networks || []).slice(0, 12).map((item) => ({
    label: item.name || `AS${item.asn}`,
    flag: flag(item.country),
    count: item.count,
    meta: `AS${item.asn} · ${number.format(item.ips)} ${item.ips === 1 ? "address" : "addresses"} · ${percent.format(share(item.count, total))}`,
  })), geo ? "No resolved networks in this window" : "Geolocation unavailable");

  renderRanked("source-ips", (view.source_ips || []).slice(0, 12).map((item) => ({
    label: item.value,
    flag: flag(item.country),
    count: item.count,
    meta: [item.country ? countryName(item.country) : "", item.asn ? `AS${item.asn} ${item.network || ""}`.trim() : ""].filter(Boolean).join(" · ") || "Location unknown",
  })));

  const simple = (values) => (values || []).slice(0, 15).map((item) => ({ label: item.value, count: item.count }));
  renderRanked("usernames", simple(view.usernames));
  renderRanked("passwords", simple(view.passwords));
  renderRanked("paths", simple(view.paths));

  renderRanked("sensors", (view.sources || []).map((item) => ({
    label: item.source_id,
    tag: item.kind === "decoy" ? "decoy" : "host",
    count: item.count,
    meta: `${percent.format(share(item.count, total))} of observations`,
  })), "No sensors reported in this window");
}

// ---------- address family ----------

function renderIPVersions(view) {
  const container = document.getElementById("ip-versions");
  container.replaceChildren();
  container.classList.remove("is-empty");
  const versions = view.ip_versions || {};
  const parts = [
    ["ipv4", "IPv4", Number(versions.ipv4 || 0), versions.ipv4_addresses],
    ["ipv6", "IPv6", Number(versions.ipv6 || 0), versions.ipv6_addresses],
    ["other", "Unattributed", Number(versions.unattributed || 0), null],
  ].filter(([key, , count]) => key !== "other" || count > 0);
  const total = parts.reduce((sum, [, , count]) => sum + count, 0);
  if (!total) {
    container.classList.add("is-empty");
    container.appendChild(el("p", "empty-state", "No accepted source IPs"));
    return;
  }
  const bar = el("div", "ipver-bar");
  const legend = el("div", "ipver-legend");
  for (const [key, label, count, addresses] of parts) {
    if (count) {
      const segment = el("div", `ipver-seg ${key}`);
      segment.style.flex = `${count} ${count} 0%`;
      bar.appendChild(segment);
    }
    const row = el("span", `key ${key}`, `${label} ${percent.format(share(count, total))}`);
    row.appendChild(el("b", "", `${number.format(count)} obs${addresses != null ? ` · ${number.format(addresses)} IPs` : ""}`));
    legend.appendChild(row);
  }
  container.append(bar, legend);
  setText("ip-versions-note", versions.unattributed
    ? "Counts every accepted observation. Unattributed observations came from addresses beyond the ledger's per-period limit of 10,000 distinct values."
    : "Counts every accepted observation, so IPv4 and IPv6 add up to the total. The published rollup files list only the top 100 addresses per period.");
}

// ---------- world map ----------

let mapPaths = new Map();

function highlightCountry(code, on) {
  const path = mapPaths.get(code);
  if (path) path.classList.toggle("is-active", on);
}

function renderMap(view) {
  const container = document.getElementById("map");
  const legend = document.getElementById("map-legend");
  container.replaceChildren();
  legend.replaceChildren();
  mapPaths = new Map();
  const world = state.world;
  if (!world) {
    container.appendChild(el("p", "empty-state", "The world map could not be loaded."));
    return;
  }
  const geo = Boolean(state.insights.geolocation);
  const counts = new Map((view.countries || []).map((item) => [item.code, item]));
  const total = view.total;
  const root = svg("svg", { viewBox: `0 0 ${world.width} ${world.height}`, preserveAspectRatio: "xMidYMid meet" });
  const defs = svg("defs", {}, root);
  const glow = svg("filter", { id: "glow", x: "-50%", y: "-50%", width: "200%", height: "200%" }, defs);
  svg("feGaussianBlur", { stdDeviation: "3", result: "blur" }, glow);
  const merge = svg("feMerge", {}, glow);
  svg("feMergeNode", { in: "blur" }, merge);
  svg("feMergeNode", { in: "SourceGraphic" }, merge);
  if (world.sphere) svg("path", { d: world.sphere, class: "sphere" }, root);
  if (world.graticule) svg("path", { d: world.graticule, class: "graticule" }, root);
  const land = svg("g", {}, root);
  for (const country of world.countries) {
    const item = counts.get(country.id);
    const value = item ? item.count : 0;
    const path = svg("path", { d: country.d, class: `country lvl-${level(value)}${value ? " has-data" : ""}` }, land);
    mapPaths.set(country.id, path);
    bindTooltip(path, () => [
      `${flag(country.id)} ${countryName(country.id)}`,
      value
        ? [
          { label: "Observations", value: number.format(value) },
          { label: "Share", value: percent.format(share(value, total)) },
          { label: "Source IPs", value: number.format(item.ips) },
        ]
        : [{ label: "Observations", value: geo ? "none" : "unknown" }],
    ]);
  }

  // Bubbles on the busiest origins, so small states stay visible.
  const centroids = new Map(world.countries.map((country) => [country.id, country.c]));
  const top = (view.countries || []).filter((item) => centroids.has(item.code)).slice(0, 10);
  const maximum = top.length ? top[0].count : 1;
  const bubbles = svg("g", {}, root);
  const placed = [];
  top.forEach((item, index) => {
    const [x, y] = centroids.get(item.code);
    const radius = 2.5 + 11 * Math.sqrt(item.count / maximum);
    svg("circle", { cx: x, cy: y, r: radius.toFixed(1), class: "bubble" }, bubbles);
    const pulse = svg("circle", { cx: x, cy: y, r: radius.toFixed(1), class: "pulse" }, bubbles);
    pulse.style.animationDelay = `${(index * 0.27).toFixed(2)}s`;
    svg("circle", { cx: x, cy: y, r: 1.6, class: "bubble-core", filter: "url(#glow)" }, bubbles);
    // Label a bubble only where the code fits clear of earlier labels.
    const box = { x: x + radius + 3, y: y - 5, w: 16, h: 10 };
    const clear = placed.every((other) => box.x > other.x + other.w || box.x + box.w < other.x || box.y > other.y + other.h || box.y + box.h < other.y);
    if (index < 8 && clear) {
      placed.push(box);
      const label = svg("text", { x: box.x.toFixed(1), y: (y + 3).toFixed(1), class: "label" }, bubbles);
      label.textContent = item.code;
    }
  });
  container.appendChild(root);
  container.setAttribute("aria-label", top.length
    ? `World map of observations by source country. Top origins: ${top.slice(0, 5).map((item) => `${countryName(item.code)} ${number.format(item.count)}`).join(", ")}.`
    : "World map of observations by source country");

  const caption = document.getElementById("map-caption");
  if (!geo) {
    caption.textContent = "Geolocation data was not available for this build.";
  } else {
    const countries = view.countries || [];
    const topThree = countries.slice(0, 3).reduce((sum, item) => sum + item.count, 0);
    const unlocated = Number(view.unlocated || 0);
    caption.textContent = `${number.format(countries.length)} source countries. The top three account for ${percent.format(share(topThree, total))} of observations${unlocated ? `; ${number.format(unlocated)} could not be located` : ""}.`;
  }

  const steps = el("div", "steps");
  const labels = ["0", "1+", "10+", "100+", "1k+", "10k+", "100k+"];
  labels.forEach((text, index) => {
    const step = el("div", "step");
    const swatch = el("span", "swatch");
    swatch.style.background = `var(--seq-${index})`;
    step.append(swatch, el("span", "", text));
    steps.appendChild(step);
  });
  legend.append(el("span", "", "Observations per country"), steps);
}

// ---------- bar charts ----------

function renderBars(containerId, points, options) {
  const container = document.getElementById(containerId);
  container.replaceChildren();
  container.classList.remove("is-empty");
  if (!points.length) {
    container.classList.add("is-empty");
    container.appendChild(el("p", "empty-state", "No accepted observations in this window"));
    return;
  }
  const width = Math.max(260, Math.round(container.clientWidth) || 640);
  const height = options.height;
  const values = points.map((point) => options.series.reduce((sum, series) => sum + (Number(series.value(point)) || 0), 0));
  const maximum = Math.max(1, ...values);
  const step = niceStep(maximum, 4);
  const top = Math.ceil(maximum / step) * step;
  const left = Math.min(64, Math.max(30, number.format(top).length * 6.4 + 10));
  const right = width;
  const plotTop = 8;
  const bottom = height - 26;
  const y = (value) => bottom - (value / top) * (bottom - plotTop);

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}` });
  const defs = svg("defs", {}, root);
  const hatch = svg("pattern", { id: `hatch-${containerId}`, width: 4, height: 4, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" }, defs);
  svg("rect", { width: 1.2, height: 4, fill: "rgb(99 120 142 / 45%)" }, hatch);

  for (let tick = 0; tick <= top; tick += step) {
    svg("line", { x1: left, x2: right, y1: y(tick).toFixed(1), y2: y(tick).toFixed(1), class: "grid" }, root);
    svg("text", { x: left - 6, y: (y(tick) + 3).toFixed(1), "text-anchor": "end", class: "axis" }, root).textContent = compact.format(tick);
  }

  const slot = (right - left) / points.length;
  const gap = slot > 6 ? 2 : slot > 2.5 ? 1 : 0;
  const barWidth = Math.max(0.8, slot - gap);
  points.forEach((point, index) => {
    const x = left + index * slot + gap / 2;
    let base = bottom;
    const missing = options.series.every((series) => series.value(point) == null);
    if (missing) {
      svg("rect", { x: x.toFixed(2), y: plotTop, width: barWidth.toFixed(2), height: (bottom - plotTop).toFixed(1), fill: `url(#hatch-${containerId})` }, root);
    } else {
      for (const series of options.series) {
        const value = Number(series.value(point)) || 0;
        if (!value) continue;
        const barHeight = Math.max(1, bottom - y(value));
        svg("rect", {
          x: x.toFixed(2),
          y: (base - barHeight).toFixed(2),
          width: barWidth.toFixed(2),
          height: barHeight.toFixed(2),
          rx: barWidth > 6 ? 1.5 : 0,
          class: series.className,
        }, root);
        base -= barHeight;
      }
    }
    const hit = svg("rect", { x: (left + index * slot).toFixed(2), y: plotTop, width: slot.toFixed(2), height: bottom - plotTop, class: "hit" }, root);
    bindTooltip(hit, () => {
      const date = new Date(point.start);
      const title = options.hourly ? formatHour(date) : `${formatDay(date)} UTC`;
      if (missing) return [title, [{ label: options.missingLabel || "Not retained", value: "" }]];
      const rows = options.series.map((series) => ({ label: series.label, key: series.key, value: number.format(Number(series.value(point)) || 0) }));
      if (options.series.length > 1) rows.push({ label: "Total", value: number.format(values[index]) });
      return [title, rows];
    });
  });

  // X axis: label calendar boundaries (midnight for multi-day hourly
  // series), thinned so labels never crowd.
  const dates = points.map((point) => new Date(point.start));
  let candidates;
  if (options.hourly && points.length > 48) {
    candidates = dates.map((date, index) => (date.getUTCHours() === 0 ? index : -1)).filter((index) => index >= 0);
  } else if (options.hourly) {
    candidates = dates.map((date, index) => (date.getUTCHours() % 3 === 0 ? index : -1)).filter((index) => index >= 0);
  } else {
    candidates = dates.map((date, index) => (date.getUTCDay() === 1 || points.length <= 16 ? index : -1)).filter((index) => index >= 0);
  }
  const maxLabels = Math.max(2, Math.floor((right - left) / 70));
  const every = Math.max(1, Math.ceil(candidates.length / maxLabels));
  candidates.forEach((index, position) => {
    if ((candidates.length - 1 - position) % every !== 0) return;
    const date = dates[index];
    const label = options.hourly && points.length <= 48
      ? date.toISOString().slice(11, 16)
      : date.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
    const x = left + index * slot + (options.hourly && points.length > 48 ? 0 : slot / 2);
    if (x < left + 14 || x > right - 14) return;
    svg("line", { x1: x.toFixed(1), x2: x.toFixed(1), y1: bottom, y2: bottom + 4, class: "grid" }, root);
    svg("text", { x: x.toFixed(1), y: height - 8, "text-anchor": "middle", class: "axis" }, root).textContent = label;
  });
  container.appendChild(root);
}

function renderTimelines(view) {
  const { hourly, points } = seriesForRange(view);
  const unit = hourly ? "hour" : "day";
  setText("timeline-title", `Observations per ${unit}`);
  setText("timeline-caption", `Accepted observations by attack vector, ${points.length} ${unit}s, UTC.`);
  renderBars("timeline", points, {
    hourly,
    height: 280,
    series: [
      { key: "ssh", label: "SSH", className: "fill-ssh", value: (point) => point.ssh },
      { key: "http", label: "HTTP", className: "fill-http", value: (point) => point.http },
    ],
  });
  setText("ips-title", `Active source IPs per ${unit}`);
  const missing = points.filter((point) => point.source_ips == null).length;
  setText("ips-caption", missing
    ? `Distinct addresses seen in each ${unit}. Hatched ${unit}s are older than the ledger keeps full address sets for.`
    : `Distinct addresses seen in each ${unit}.`);
  renderBars("ips-chart", points, {
    hourly,
    height: 200,
    missingLabel: "Full address set no longer retained",
    series: [{ key: "ssh", label: "Source IPs", className: "fill-ips", value: (point) => point.source_ips }],
  });
}

// ---------- heatmap ----------

function renderHeatmap() {
  const container = document.getElementById("heatmap");
  container.replaceChildren();
  const hourly = state.insights.hourly || [];
  if (!hourly.length) {
    container.appendChild(el("p", "empty-state", "No hourly observations"));
    return;
  }
  const sums = Array.from({ length: 7 }, () => new Array(24).fill(0));
  const slots = Array.from({ length: 7 }, () => new Array(24).fill(0));
  for (const point of hourly) {
    const date = new Date(point.start);
    const weekday = (date.getUTCDay() + 6) % 7; // Monday first
    sums[weekday][date.getUTCHours()] += Number(point.total || 0);
    slots[weekday][date.getUTCHours()] += 1;
  }
  const averages = sums.map((row, day) => row.map((sum, hour) => (slots[day][hour] ? sum / slots[day][hour] : 0)));
  const maximum = Math.max(1, ...averages.flat());
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const width = 600;
  const left = 30;
  const top = 4;
  const cell = (width - left) / 24;
  const rowHeight = Math.min(cell, 22);
  const height = top + rowHeight * 7 + 18;
  const root = svg("svg", { viewBox: `0 0 ${width} ${height}` });
  averages.forEach((row, day) => {
    svg("text", { x: 0, y: (top + day * rowHeight + rowHeight / 2 + 3).toFixed(1) }, root).textContent = days[day];
    row.forEach((value, hour) => {
      // Relative steps: the heatmap shows rhythm, not absolute volume.
      const step = value ? Math.max(1, Math.ceil((value / maximum) * 6)) : 0;
      const rect = svg("rect", {
        x: (left + hour * cell).toFixed(1),
        y: (top + day * rowHeight).toFixed(1),
        width: cell.toFixed(1),
        height: rowHeight.toFixed(1),
        rx: 2,
        class: "cell",
        fill: `var(--seq-${step})`,
      }, root);
      bindTooltip(rect, () => [
        `${days[day]} ${String(hour).padStart(2, "0")}:00–${String(hour + 1).padStart(2, "0")}:00 UTC`,
        [
          { label: "Average per hour", value: number.format(Math.round(value)) },
          { label: "Hours sampled", value: number.format(slots[day][hour]) },
        ],
      ]);
    });
  });
  for (let hour = 0; hour < 24; hour += 3) {
    svg("text", { x: (left + hour * cell + 1).toFixed(1), y: height - 4 }, root).textContent = String(hour).padStart(2, "0");
  }
  container.appendChild(root);
}

// ---------- orchestration ----------

function render() {
  const view = currentWindow();
  for (const button of document.querySelectorAll(".range button")) {
    const available = (state.insights.windows || []).some((item) => item.id === button.dataset.range);
    button.disabled = !available;
    button.setAttribute("aria-checked", String(button.dataset.range === (view && view.id)));
  }
  for (const tag of document.querySelectorAll("[data-range-tag]")) tag.textContent = RANGES[view ? view.id : "all"];
  if (!view) {
    renderUnavailableDashboard("No accepted observations yet");
    return;
  }
  renderKPIs(view);
  renderMap(view);
  renderLists(view);
  renderIPVersions(view);
  renderTimelines(view);
  renderHeatmap();
  state.width = document.body.clientWidth;
}

function setRange(range) {
  if (!(range in RANGES) || range === state.range) return;
  state.range = range;
  try {
    const url = new URL(window.location.href);
    url.searchParams.set("range", range);
    window.history.replaceState(null, "", url);
  } catch {
    // Some embedded viewers forbid history changes; the range still applies.
  }
  tooltip.hide();
  render();
}

function renderUnavailableDashboard(message) {
  for (const id of ["countries", "networks", "source-ips", "usernames", "passwords", "paths", "sensors"]) {
    renderRanked(id, [], message);
  }
  for (const id of ["map", "timeline", "ips-chart", "heatmap", "ip-versions"]) {
    const node = document.getElementById(id);
    node.replaceChildren(el("p", "empty-state", message));
    node.classList.add("is-empty");
  }
}

function setupControls() {
  const requested = new URLSearchParams(window.location.search).get("range");
  if (requested in RANGES) state.range = requested;
  for (const button of document.querySelectorAll(".range button")) {
    button.addEventListener("click", () => setRange(button.dataset.range));
  }
  document.querySelector(".range").addEventListener("keydown", (event) => {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    const buttons = [...document.querySelectorAll(".range button:not([disabled])")];
    const index = buttons.findIndex((button) => button.dataset.range === state.range);
    const next = buttons[(index + (event.key === "ArrowRight" ? 1 : buttons.length - 1)) % buttons.length];
    if (next) {
      setRange(next.dataset.range);
      next.focus();
    }
  });
  const status = document.querySelector(".status");
  const observer = "IntersectionObserver" in window ? new IntersectionObserver(([entry]) => {
    status.classList.toggle("is-stuck", entry.intersectionRatio < 1);
  }, { threshold: [1], rootMargin: "-1px 0px 0px 0px" }) : null;
  if (observer) observer.observe(status);
  window.addEventListener("resize", () => {
    window.clearTimeout(state.resizeTimer);
    state.resizeTimer = window.setTimeout(() => {
      if (state.insights && Math.abs(document.body.clientWidth - state.width) >= 8) render();
    }, 150);
  });
  window.addEventListener("scroll", () => tooltip.hide(), { passive: true });
}

async function load() {
  const [insightsResponse, worldResponse] = await Promise.all([
    fetch("data/insights.json", { cache: "no-store" }),
    fetch("world.json").catch(() => null),
  ]);
  if (!insightsResponse.ok) throw new Error("insights fetch failed");
  const insights = await insightsResponse.json();
  if (insights.schema_version !== "probing.insights/v1" || insights.label !== "self-reported suspected probes") {
    throw new Error("unexpected insights contract");
  }
  state.insights = insights;
  if (worldResponse && worldResponse.ok) {
    try {
      state.world = await worldResponse.json();
    } catch {
      state.world = null;
    }
  }
  render();

  const updatedAt = new Date(insights.updated_at);
  if (!Number.isFinite(updatedAt.getTime())) throw new Error("invalid rollup timestamp");
  const ageHours = (Date.now() - updatedAt.getTime()) / HOUR;
  if (ageHours < -1) throw new Error("rollup timestamp is in the future");
  const freshness = document.getElementById("freshness");
  freshness.textContent = ageHours > 3 ? "Data is stale" : "Data is current";
  if (ageHours > 3) freshness.classList.add("stale");
  setText("updated", `Last accepted batch: ${updatedAt.toISOString()}`);
}

setupControls();
load().catch(() => {
  renderUnavailableDashboard("Data unavailable");
  const freshness = document.getElementById("freshness");
  freshness.textContent = "Data unavailable";
  freshness.classList.add("error");
  setText("updated", "The published data files could not be validated.");
});
