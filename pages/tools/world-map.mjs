// Regenerates pages/world.json, the pre-projected world map the dashboard
// draws. It is committed so the dashboard needs no third-party scripts and no
// projection code at run time. Country shapes come from Natural Earth (public
// domain) via world-atlas: 1:110m for most countries, 1:50m for small states
// that the coarser file omits. Antarctica is dropped.
//
//   cd pages/tools
//   npm install --no-save d3-geo@3.1.1 topojson-client@3.1.0 world-atlas@2.0.2 i18n-iso-countries@7.14.0
//   node world-map.mjs ../world.json
import { readFileSync, writeFileSync } from "node:fs";
import { geoNaturalEarth1, geoPath, geoArea, geoGraticule10 } from "d3-geo";
import { feature } from "topojson-client";
import countries from "i18n-iso-countries";

const load = (res) => { const t = JSON.parse(readFileSync(new URL(`./node_modules/world-atlas/countries-${res}.json`, import.meta.url))); return feature(t, t.objects.countries).features.filter((f) => f.id !== "010"); };
const coarse = load("110m"), fine = load("50m");
const W = 960;
const all = { type: "FeatureCollection", features: coarse };
const projection = geoNaturalEarth1().fitWidth(W, all);
let path = geoPath(projection);
const [[, y0], [, y1]] = path.bounds(all);
const [tx, ty] = projection.translate();
projection.translate([tx, ty - y0 + 2]);
path = geoPath(projection);
const H = Math.ceil(y1 - y0 + 4);
const round = (d) => d.replace(/-?\d+(\.\d+)?/g, (n) => String(Math.round(Number(n) * 10) / 10));
const fix = { Kosovo: "XK", "N. Cyprus": "CY", Somaliland: "SO" };
const codeOf = (f) => (f.id && f.id !== "-99" && countries.numericToAlpha2(f.id)) || fix[f.properties.name] || null;
const centroid = (f) => {
  let best = f.geometry, bestArea = -1;
  if (f.geometry.type === "MultiPolygon") for (const c of f.geometry.coordinates) { const g = { type: "Polygon", coordinates: c }; const a = geoArea(g); if (a > bestArea) { bestArea = a; best = g; } }
  return path.centroid(best).map((v) => Math.round(v * 10) / 10);
};
const merged = new Map();
const add = (f) => {
  const id = codeOf(f); const d = path(f);
  if (!id || !d) return;
  const prev = merged.get(id);
  if (prev) { prev.d += round(d); return; }
  merged.set(id, { id, d: round(d), c: centroid(f) });
};
coarse.forEach(add);
const coarseIds = new Set(merged.keys());
for (const f of fine) { const id = codeOf(f); if (id && !coarseIds.has(id)) add(f); }
const sphere = round(path({ type: "Sphere" }));
const graticule = round(path(geoGraticule10()));
const out = { sphere, graticule, source: "Natural Earth 1:110m, small states from 1:50m, via world-atlas 2.0.2 (public domain)", projection: "Natural Earth I", width: W, height: H, countries: [...merged.values()].sort((a, b) => a.id.localeCompare(b.id)) };
const json = JSON.stringify(out);
writeFileSync(process.argv[2], json + "\n");
console.log(merged.size, json.length, W, H);
