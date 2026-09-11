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
    addText(row, "span", ` - ${number.format(item.count)}`);
    list.appendChild(row);
  }
  if (!values.length) addText(list, "li", "No accepted values");
}

function renderChart(periods) {
  const values = periods.slice(-168);
  const container = document.getElementById("chart");
  if (!values.length) {
    addText(container, "p", "No accepted hourly observations");
    return;
  }
  const namespace = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(namespace, "svg");
  svg.setAttribute("viewBox", "0 0 1000 240");
  const maximum = Math.max(1, ...values.map((item) => Number(item.total || 0)));
  for (const y of [20, 110, 200]) {
    const line = document.createElementNS(namespace, "line");
    line.setAttribute("x1", "0");
    line.setAttribute("x2", "1000");
    line.setAttribute("y1", String(y));
    line.setAttribute("y2", String(y));
    svg.appendChild(line);
  }
  const points = values.map((item, index) => {
    const x = values.length === 1 ? 500 : index * (1000 / (values.length - 1));
    const y = 200 - (Number(item.total || 0) / maximum) * 180;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const polyline = document.createElementNS(namespace, "polyline");
  polyline.setAttribute("points", points.join(" "));
  svg.appendChild(polyline);
  const label = document.createElementNS(namespace, "text");
  label.setAttribute("x", "4");
  label.setAttribute("y", "235");
  label.textContent = `${values[0].start} to ${values[values.length - 1].end} UTC`;
  svg.appendChild(label);
  container.appendChild(svg);
}

function renderSources(periods) {
  const sources = aggregate(
    periods.flatMap((period) => period.sources || []),
    (item) => `${item.source_id}\u0000${item.source_epoch}`,
  );
  document.getElementById("source-count").textContent = number.format(sources.length);
  const body = document.getElementById("sources");
  for (const source of sources) {
    const [sourceID, sourceEpoch] = source.value.split("\u0000");
    const row = document.createElement("tr");
    addText(row, "td", sourceID);
    addText(row, "td", sourceEpoch);
    addText(row, "td", number.format(source.count));
    body.appendChild(row);
  }
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
  const freshness = document.getElementById("freshness");
  freshness.textContent = "Data unavailable";
  freshness.classList.add("error");
  document.getElementById("updated").textContent = "The published rollup files could not be validated.";
});
