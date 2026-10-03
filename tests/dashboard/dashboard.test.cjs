"use strict";

const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const {resolve} = require("node:path");
const vm = require("node:vm");
const {test} = require("node:test");
const {parseHTML} = require("linkedom");

const assets = resolve(__dirname, "../../internal/dashboard/assets");
const script = readFileSync(process.env.REQSENTRY_DASHBOARD_SCRIPT || resolve(assets, "app.js"), "utf8");
const html = readFileSync(resolve(assets, "index.html"), "utf8");
const flush = async () => {
  for (let i = 0; i < 4; i++) await new Promise(setImmediate);
};

function snapshot(rate = 10) {
  return {
    server: "test-server", at: new Date().toISOString(), analysis_active: true,
    live: {
      requests_per_second: rate, requests: 600, active_ips: 5,
      statuses: {404: 60, 301: 10}, status_families: [0, 0, 520, 10, 60, 10],
      window_dropped: 0, degraded: false,
    },
    health: {CPUPercent: 1.5, MemoryUsedPercent: 10, Load1: 0, Load5: 0.2, Load15: 0.1},
    php_fpm: [{Stats: {"active processes": 3, "idle processes": 7}}],
    recent_incident_summary: {would_block_ips: 1, suspicious_ips: 2, active_incidents: 3},
  };
}

function dashboard() {
  const {window, document} = parseHTML(html);
  // Linkedom exposes a select getter but omits the browser's value setter.
  const selectValue = Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype, "value");
  Object.defineProperty(window.HTMLSelectElement.prototype, "value", {
    ...selectValue,
    set(value) {
      for (const option of this.options) option.selected = option.value === value;
    },
  });
  const root = document.getElementById("content");
  const location = {hash: ""};
  let now = 1700000000000;
  let focused = document.body;
  // Linkedom models DOM changes; focus/layout behavior is verified in the browser.
  Object.defineProperty(document, "activeElement", {get: () => focused});
  const requests = [];
  const gates = new Map();
  const failures = new Set();
  let stream;
  class Events {
    constructor() { this.listeners = new Map(); stream = this; }
    addEventListener(type, callback) { this.listeners.set(type, callback); }
  }
  const initial = snapshot();
  const data = {
    stats: {live: initial.live, history: [{requests: 600, status_404: 60, status_5xx: 10, incidents: 3, cpu_percent: 1.5}], coverage: "test coverage"},
    server: {...initial, name: initial.server},
    incidents: {incidents: []},
    errors: {errors: [], sources: [], timeline: [], coverage: "test error coverage"},
    sites: {sites: []},
  };
  const context = vm.createContext({
    window, document, location, Node: window.Node, URLSearchParams,
    Date: class extends Date {static now() { return now; }},
    EventSource: Events,
    fetch: async (url) => {
      requests.push(url);
      const key = url.split("/").pop().split("?")[0];
      if (gates.has(key)) await gates.get(key).promise;
      return {ok: !failures.has(key), status: failures.has(key) ? 503 : 200,
        json: async () => JSON.parse(JSON.stringify(data[key]))};
    },
  });
  vm.runInContext(script, context);
  return {
    root, document, requests,
    run: (code) => vm.runInContext(code, context),
    advance: (ms) => { now += ms; },
    focus: (element) => { focused = element; },
    live: (value) => stream.listeners.get("snapshot")({data: JSON.stringify(value)}),
    count: (key) => requests.filter(url => url.split("/").pop().split("?")[0] === key).length,
    fail: (key) => failures.add(key),
    recover: (key) => failures.delete(key),
    hold: (key) => {
      let release;
      const promise = new Promise(done => { release = done; });
      gates.set(key, {promise});
      return () => { gates.delete(key); release(); };
    },
    change: (element) => element.dispatchEvent(new window.Event("change")),
    navigate: async (route) => { location.hash = "#" + route; await vm.runInContext("render()", context); },
    metric: (label) => [...root.querySelectorAll(".metric")].find(card => card.querySelector(".label").textContent === label).querySelector(".value").textContent,
  };
}

test("live snapshots preserve charts, tables and filter drafts while updating metrics", async () => {
  const h = dashboard(); await flush();
  assert.ok(h.root.querySelector(".metrics"), h.root.textContent);
  const grid = h.root.firstElementChild;
  const chart = h.root.querySelector("svg");
  const table = h.root.querySelector("table");
  const input = h.root.querySelector('input[aria-label="Error category"]');
  input.value = "unfinished category"; h.focus(input);
  table.parentElement.scrollLeft = 120;
  const count = h.requests.length;
  for (let i = 1; i <= 20; i++) h.live(snapshot(i));
  await flush();
  assert.ok(h.root.firstElementChild === grid, "metric grid should stay mounted");
  assert.ok(h.root.querySelector("svg") === chart, "chart should stay mounted");
  assert.ok(h.root.querySelector("table") === table, "table should stay mounted");
  assert.equal(table.parentElement.scrollLeft, 120);
  assert.equal(input.value, "unfinished category");
  assert.equal(h.metric("Requests / second"), "20");
  assert.equal(h.requests.length, count);
  const missing = snapshot(0); missing.health = {}; missing.php_fpm = [];
  h.live(missing);
  assert.equal(h.metric("CPU"), "—");
  assert.equal(h.metric("PHP-FPM"), "—");
});

test("slow history refresh retains the view and coalesces incoming snapshots", async () => {
  const h = dashboard(); await flush();
  const grid = h.root.firstElementChild;
  const release = h.hold("stats");
  h.advance(31000); h.live(snapshot(40)); await flush();
  assert.ok(h.root.firstElementChild === grid, "metric grid should stay mounted");
  for (let i = 41; i <= 60; i++) h.live(snapshot(i));
  await flush();
  assert.equal(h.count("stats"), 2);
  assert.equal(h.count("server"), 2);
  assert.equal(h.count("incidents"), 2);
  assert.equal(h.metric("Requests / second"), "60");
  assert.ok(h.root.childElementCount > 0);
  release(); await flush();
  assert.ok(h.root.firstElementChild !== grid, "completed history should replace the view");
  assert.equal(h.metric("Requests / second"), "60");
});

test("editing a filter postpones background refresh but still accepts explicit changes", async () => {
  const h = dashboard(); await flush();
  const input = h.root.querySelector('input[aria-label="Error category"]');
  input.value = "upstream_timeout"; h.focus(input);
  h.advance(31000); h.live(snapshot(70)); await flush();
  assert.equal(h.count("stats"), 1);
  assert.equal(h.metric("Requests / second"), "70");
  assert.ok(h.root.querySelector('input[aria-label="Error category"]') === input, "filter should stay mounted");
  h.change(input); await flush();
  assert.equal(h.count("stats"), 2);
  assert.ok(h.requests.some(url => url.includes("category=upstream_timeout")));
});

test("a filter focused during a pending background refresh keeps its draft", async () => {
  const h = dashboard(); await flush();
  const release = h.hold("errors");
  h.advance(31000); h.live(snapshot(80)); await flush();
  const input = h.root.querySelector('input[aria-label="Error category"]');
  input.value = "draft typed during refresh"; h.focus(input);
  release(); await flush();
  assert.ok(h.root.querySelector('input[aria-label="Error category"]') === input, "filter should stay mounted");
  assert.equal(input.value, "draft typed during refresh");
});

test("failed history refresh preserves live data, backs off and recovers", async () => {
  const h = dashboard(); await flush();
  const grid = h.root.firstElementChild;
  h.fail("stats"); h.advance(31000); h.live(snapshot(90)); await flush();
  assert.ok(h.root.contains(grid));
  assert.ok(h.root.querySelector(".overview-error"));
  for (let i = 91; i <= 100; i++) h.live(snapshot(i));
  await flush();
  assert.equal(h.count("stats"), 2);
  assert.equal(h.metric("Requests / second"), "100");
  h.recover("stats"); h.advance(31000); h.live(snapshot(101)); await flush();
  assert.equal(h.count("stats"), 3);
  assert.equal(h.root.querySelector(".overview-error"), null);
  assert.equal(h.metric("Requests / second"), "101");
});

test("a pending overview response cannot overwrite navigation", async () => {
  const h = dashboard(); await flush();
  const release = h.hold("errors");
  h.advance(31000); h.live(snapshot()); await flush();
  await h.navigate("sites");
  const content = h.root.innerHTML;
  release(); await flush();
  assert.equal(h.document.getElementById("page-title").textContent, "Sites");
  assert.equal(h.root.innerHTML, content);
});

test("snapshots during initial loading do not restart requests or lose the latest data", async () => {
  const h = dashboard();
  const release = h.hold("errors"); await flush();
  for (let i = 1; i <= 10; i++) h.live(snapshot(i));
  await flush();
  assert.equal(h.count("stats"), 1);
  assert.equal(h.count("errors"), 1);
  assert.match(h.root.textContent, /Loading dashboard/);
  release(); await flush();
  assert.equal(h.metric("Requests / second"), "10");
});
