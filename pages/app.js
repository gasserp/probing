"use strict";

const number = new Intl.NumberFormat("en-US");

function addText(parent, tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = String(value);
  if (className) node.className = className;
  parent.appendChild(node);
  return node;
}

function aggregate(items, key) {
  const totals = new Map();
  for (const item of items) {
    const value = key(item);
    totals.set(value, (totals.get(value) || 0) + Number(item.count || 0));
  }
  return [...totals.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value));
}

function renderList(id, values) {
  const list = document.getElementById(id);
  for (const item of values.slice(0, 20)) {
    const row = document.createElement("li");
    row.appendChild(document.createTextNode(item.value));
    addText(row, "span", number.format(item.count));
    list.appendChild(row);
  }
  if (!values.length) addText(list, "li", "No accepted values", "empty-row");
}

function hourTickStep(maxHoursBack) {
  const steps = [1, 2, 3, 6, 12, 24, 48, 72, 168];
  for (const step of steps) {
    if (Math.ceil(maxHoursBack / step) <= 6) return step;
  }
  return steps[steps.length - 1];
}

function axisStep(maxValue) {
  let step = 10;
  while (maxValue / step > 5) step *= 10;
  return step;
}

function renderChart(periods) {
  const values = periods.slice(-168);
  const container = document.getElementById("chart");
  if (!values.length) {
    container.classList.add("is-empty");
    addText(container, "p", "No accepted hourly observations", "empty-state");
    return;
  }
  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.setAttribute("viewBox", "0 0 1000 240");
  svg.setAttribute("preserveAspectRatio", "none");
  const defs = document.createElementNS(namespace, "defs");
  const gradient = document.createElementNS(namespace, "linearGradient");
  gradient.setAttribute("id", "chart-fill");
  gradient.setAttribute("x1", "0");
  gradient.setAttribute("x2", "0");
  gradient.setAttribute("y1", "0");
  gradient.setAttribute("y2", "1");
  const start = document.createElementNS(namespace, "stop");
  start.setAttribute("offset", "0%");
  start.setAttribute("stop-color", "#6ee7f2");
  start.setAttribute("stop-opacity", ".28");
  const end = document.createElementNS(namespace, "stop");
  end.setAttribute("offset", "100%");
  end.setAttribute("stop-color", "#6ee7f2");
  end.setAttribute("stop-opacity", "0");
  gradient.append(start, end);
  defs.appendChild(gradient);
  svg.appendChild(defs);

  const plotLeft = 54;
  const plotRight = 1000;
  const plotTop = 10;
  const plotBottom = 200;
  const maximum = Math.max(1, ...values.map((item) => Number(item.total || 0)));
  const step = axisStep(maximum);
  const niceMax = Math.ceil(maximum / step) * step;

  for (let tick = 0; tick <= niceMax; tick += step) {
    const y = plotBottom - (tick / niceMax) * (plotBottom - plotTop);
    const line = document.createElementNS(namespace, "line");
    line.setAttribute("x1", String(plotLeft));
    line.setAttribute("x2", String(plotRight));
    line.setAttribute("y1", y.toFixed(2));
    line.setAttribute("y2", y.toFixed(2));
    svg.appendChild(line);
    const tickLabel = document.createElementNS(namespace, "text");
    tickLabel.setAttribute("x", String(plotLeft - 6));
    tickLabel.setAttribute("y", (y + 3).toFixed(2));
    tickLabel.setAttribute("text-anchor", "end");
    tickLabel.textContent = number.format(tick);
    svg.appendChild(tickLabel);
  }

  const timestamps = values.map((item) => new Date(item.end).getTime());
  const maxTime = timestamps[timestamps.length - 1];
  const totalHoursSpan = Math.round((maxTime - timestamps[0]) / 3600000);
  const xForHoursBack = (hoursBack) => totalHoursSpan === 0
    ? (plotLeft + plotRight) / 2
    : plotRight - (hoursBack / totalHoursSpan) * (plotRight - plotLeft);

  const points = values.map((item, index) => {
    const hoursBack = (maxTime - timestamps[index]) / 3600000;
    const x = xForHoursBack(hoursBack);
    const y = plotBottom - (Number(item.total || 0) / niceMax) * (plotBottom - plotTop);
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const polyline = document.createElementNS(namespace, "polyline");
  const pointString = points.join(" ");
  const area = document.createElementNS(namespace, "polygon");
  area.setAttribute("points", `${plotLeft},${plotBottom} ${pointString} ${plotRight},${plotBottom}`);
  svg.appendChild(area);
  polyline.setAttribute("points", pointString);
  svg.appendChild(polyline);

  const hourStep = hourTickStep(totalHoursSpan);
  for (let hoursBack = 0; hoursBack <= totalHoursSpan; hoursBack += hourStep) {
    const x = xForHoursBack(hoursBack);
    const xLabel = document.createElementNS(namespace, "text");
    xLabel.setAttribute("x", x.toFixed(2));
    xLabel.setAttribute("y", "213");
    xLabel.setAttribute("text-anchor", hoursBack === 0 ? "end" : hoursBack + hourStep > totalHoursSpan ? "start" : "middle");
    xLabel.textContent = hoursBack === 0 ? "now" : `-${hoursBack}h`;
    svg.appendChild(xLabel);
  }

  const range = document.createElementNS(namespace, "text");
  range.setAttribute("x", String(plotLeft));
  range.setAttribute("y", "233");
  range.textContent = `${values[0].start} to ${values[values.length - 1].end} UTC`;
  svg.appendChild(range);

  container.appendChild(svg);
}

function renderSources(periods) {
  const sources = aggregate(
    periods.flatMap((period) => period.sources || []),
    (item) => `${item.source_id}\u0000${item.source_epoch}`,
  );
  document.getElementById("source-count").textContent = number.format(sources.length);
}

function classifyIPVersion(ip) {
  return ip.includes(":") ? "ipv6" : "ipv4";
}

function renderIPVersions(periods) {
  const container = document.getElementById("ip-versions");
  const counts = { ipv4: 0, ipv6: 0 };
  for (const item of periods.flatMap((period) => period.source_ips || [])) {
    counts[classifyIPVersion(item.value)] += Number(item.count || 0);
  }
  const total = counts.ipv4 + counts.ipv6;
  if (!total) {
    container.classList.add("is-empty");
    addText(container, "p", "No accepted source IPs", "empty-state");
    return;
  }
  const bar = document.createElement("div");
  bar.className = "ipver-bar";
  const legend = document.createElement("div");
  legend.className = "ipver-legend";
  for (const [key, label] of [["ipv4", "IPv4"], ["ipv6", "IPv6"]]) {
    const count = counts[key];
    const pct = (count / total) * 100;
    if (count) {
      const seg = document.createElement("div");
      seg.className = `ipver-seg ${key}`;
      seg.style.flex = `${count} ${count} 0%`;
      bar.appendChild(seg);
    }
    addText(legend, "span", `${label} — ${pct.toFixed(1)}% (${number.format(count)})`, `ipver-key ${key}`);
  }
  container.appendChild(bar);
  container.appendChild(legend);
}

function renderUnavailableDashboard() {
  document.getElementById("chart").replaceChildren();
  document.getElementById("ip-versions").replaceChildren();
  document.getElementById("usernames").replaceChildren();
  document.getElementById("paths").replaceChildren();
  document.getElementById("source-ips").replaceChildren();

  renderChart([]);
  renderIPVersions([]);
  for (const id of ["usernames", "paths", "source-ips"]) renderList(id, []);
}

async function load() {
  const names = ["hourly", "yearly"];
  const responses = await Promise.all(names.map((name) => fetch(`data/${name}.json`, { cache: "no-store" })));
  if (responses.some((response) => !response.ok)) throw new Error("rollup fetch failed");
  const [hourly, yearly] = await Promise.all(responses.map((response) => response.json()));
  if (hourly.label !== "self-reported suspected probes" || yearly.label !== hourly.label) {
    throw new Error("unexpected rollup contract");
  }

  const yearlyPeriods = Array.isArray(yearly.periods) ? yearly.periods : [];
  const hourlyPeriods = Array.isArray(hourly.periods) ? hourly.periods : [];
  const total = yearlyPeriods.reduce((sum, period) => sum + Number(period.total || 0), 0);
  document.getElementById("total").textContent = number.format(total);
  renderChart(hourlyPeriods);
  renderSources(yearlyPeriods);
  renderIPVersions(yearlyPeriods);
  renderList("usernames", aggregate(yearlyPeriods.flatMap((period) => period.usernames || []), (item) => item.value));
  renderList("paths", aggregate(yearlyPeriods.flatMap((period) => period.paths || []), (item) => item.value));
  renderList("source-ips", aggregate(yearlyPeriods.flatMap((period) => period.source_ips || []), (item) => item.value));

  const updatedAt = new Date(yearly.updated_at);
  if (!Number.isFinite(updatedAt.getTime())) throw new Error("invalid rollup timestamp");
  const ageHours = (Date.now() - updatedAt.getTime()) / 3600000;
  if (ageHours < -1) throw new Error("rollup timestamp is in the future");
  const freshness = document.getElementById("freshness");
  freshness.textContent = ageHours > 3 ? "Data is stale" : "Data is current";
  if (ageHours > 3) freshness.classList.add("stale");
  document.getElementById("updated").textContent = `Last accepted batch: ${updatedAt.toISOString()}`;
}

load().catch(() => {
  renderUnavailableDashboard();
  const freshness = document.getElementById("freshness");
  freshness.textContent = "Data unavailable";
  freshness.classList.add("error");
  document.getElementById("updated").textContent = "The published rollup files could not be validated.";
});
