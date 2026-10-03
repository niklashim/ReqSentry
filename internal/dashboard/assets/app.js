"use strict";

const root = document.getElementById("content");
const title = document.getElementById("page-title");
const connection = document.getElementById("connection");
const serverName = document.getElementById("server-name");
let lastLive = null;
let range = "1h";
let errorSeverity = "";
let errorAssociation = "";
let errorCategory = "";
let incidentPage = 1;
let samplePage=1;
let sampleGeneration=0;
let sampleRouteSite;
let sampleFilter={site:"",server:"",ip:"",method:"",status:"",q:"",from:"",to:""};
let incidentFilter = {
  site: "",
  ip: "",
  decision: "",
  min_score: "",
  signal: "",
  q: "",
  server: "",
  from: "",
  to: "",
};
let overviewCache = null;
let overviewCachedAt = 0;
let renderGeneration = 0;
let overviewView = null;
let overviewPending = 0;
let overviewRetryAt = 0;

function overviewValues(v, h = {}, pools = [], summary = {}, name, analysisActive) {
  const active = pools.reduce((sum, p) => sum + Number(p.Stats?.["active processes"] || 0), 0);
  const idle = pools.reduce((sum, p) => sum + Number(p.Stats?.["idle processes"] || 0), 0);
  return {
    metrics: [
      ["Requests / second", fmt(v.requests_per_second), "last complete second"],
      ["Requests / minute", fmt(v.requests), "rolling 60 seconds"],
      ["Active IPs", fmt(v.active_ips), "tracked clients"],
      ["HTTP 404", pct(v.statuses?.[404] || 0, v.requests), fmt(v.statuses?.[404] || 0) + " responses", "warn"],
      ["CPU", h.CPUPercent == null ? "—" : h.CPUPercent.toFixed(1) + "%", "latest sample"],
      ["Memory", h.MemoryUsedPercent == null ? "—" : h.MemoryUsedPercent.toFixed(1) + "%", "latest sample"],
      ["PHP-FPM", pools.length ? `${active} / ${active + idle}` : "—", "active / total workers"],
      ["Would block", fmt(summary.would_block_ips), "unique IPs · monitor only", "alert"],
      ["Suspicious IPs", fmt(summary.suspicious_ips), "last five minutes"],
      ["Active incidents", fmt(summary.active_incidents), "last five minutes"],
      ["HTTP 2xx", pct(v.status_families?.[2] || 0, v.requests), fmt(v.status_families?.[2] || 0) + " responses"],
      ["HTTP 301 / 302", `${fmt(v.statuses?.[301] || 0)} / ${fmt(v.statuses?.[302] || 0)}`, "redirect responses"],
      ["HTTP 5xx", pct(v.status_families?.[5] || 0, v.requests), fmt(v.status_families?.[5] || 0) + " responses", "warn"],
    ],
    state: [
      ["Server", name || "—"],
      ["Mode", "MONITOR"],
      ["Analysis", analysisActive ? "Active" : "Idle"],
      ["Load · 1 / 5 / 15", [h.Load1, h.Load5, h.Load15].map(x => x == null ? "—" : Number(x).toFixed(2)).join(" / ")],
      ["PHP-FPM pools", pools.length],
      ["Dropped window events", fmt(v.window_dropped)],
      ["Aggregator degraded", v.degraded ? "Yes" : "No"],
    ],
  };
}

function overviewVisible() {
  return current() === "overview" && overviewView && root.contains(overviewView.cards);
}

function updateOverviewLive() {
  if (!lastLive || !overviewVisible()) return;
  const values = overviewValues(lastLive.live, lastLive.health || {}, lastLive.php_fpm || [],
    lastLive.recent_incident_summary || {}, lastLive.server, lastLive.analysis_active);
  // Preserve the charts, controls, focus, and scroll positions between snapshots.
  const setText = (element, text) => {
    if (element.textContent !== String(text)) element.textContent = String(text);
  };
  values.metrics.forEach(([, value, sub], index) => {
    const card = overviewView.cards.children[index];
    setText(card.querySelector(".value"), value);
    setText(card.querySelector(".sub"), sub);
  });
  values.state.forEach(([, value], index) => setText(overviewView.state[index].lastElementChild, value));
}

function refreshOverviewLive() {
  updateOverviewLive();
  // Coalesce snapshots while a refresh is pending. Keep editing controls stable;
  // their change handlers request an explicit refresh with the selected filters.
  const editing = root.contains(document.activeElement) &&
    document.activeElement.matches("input, select, button");
  if (!overviewPending && !editing && Date.now() >= overviewRetryAt &&
      (!overviewVisible() || Date.now() - overviewCachedAt > 30000)) render({background: true});
}

function node(tag, text, className) {
  const n = document.createElement(tag);
  if (text !== undefined && text !== null) n.textContent = String(text);
  if (className) n.className = className;
  return n;
}
function append(parent, ...children) {
  children.forEach((c) => c && parent.append(c));
  return parent;
}
function clear(parent) {
  parent.replaceChildren();
  return parent;
}
function fmt(v) {
  return v === undefined || v === null ? "—" : Number(v).toLocaleString();
}
function pct(n, d) {
  return d ? ((100 * n) / d).toFixed(1) + "%" : "0%";
}
function when(v) {
  if (!v) return "—";
  const d = new Date(v);
  return Number.isNaN(+d) ? "—" : d.toLocaleString();
}
function link(text, href) {
  const a = node("a", text);
  a.href = href;
  return a;
}
function siteLinks(siteIDs) {
  if (!siteIDs?.length) return "—";
  const list = node("span");
  siteIDs.forEach((site, index) => {
    if (index) list.append(document.createTextNode(", "));
    list.append(link(site, "#site/" + encodeURIComponent(site)));
  });
  return list;
}
function badge(text) {
  const b = node("span", text, "badge");
  if (text === "WOULD_BLOCK") b.classList.add("bad");
  if (text === "SUSPICIOUS") b.classList.add("mid");
  return b;
}
function panel(heading) {
  const p = node("section", null, "panel");
  if (heading) p.append(node("h2", heading));
  return p;
}
function metric(label, value, sub, tone) {
  const p = node("section", null, "metric" + (tone ? " " + tone : ""));
  append(
    p,
    node("div", label, "label"),
    node("div", value, "value"),
    node("div", sub, "sub"),
  );
  return p;
}
function table(headers, rows, className = "") {
  const wrap = node("div", null, "tablewrap"),
    t = node("table", null, className),
    head = node("thead"),
    body = node("tbody"),
    tr = node("tr");
  headers.forEach((h) => tr.append(node("th", h)));
  head.append(tr);
  rows.forEach((row) => {
    const r = node("tr");
    row.forEach((value) => {
      const c = node("td");
      c.append(
        value instanceof Node
          ? value
          : document.createTextNode(
              value === undefined || value === null ? "—" : String(value),
            ),
      );
      r.append(c);
    });
    body.append(r);
  });
  append(t, head, body);
  wrap.append(t);
  return wrap;
}
function kv(label, value) {
  const p = node("div", null, "kv");
  const display = value instanceof Node
    ? append(node("span"), value)
    : node("span", value);
  append(p, node("span", label), display);
  return p;
}
function empty(message) {
  return node("div", message, "empty");
}
function note(message) {
  return node("p", message, "hint");
}
function error(message) {
  clear(root).append(node("div", message, "error"));
}
async function api(path) {
  const res = await fetch("/api/v1/" + path, { cache: "no-store" });
  if (!res.ok)
    throw new Error(
      res.status === 404 ? "Item not found" : `Request failed (${res.status})`,
    );
  return res.json();
}
function current() {
  return location.hash.slice(1) || "overview";
}
function setTitle(value) {
  title.textContent = value;
  const route = current().split("/")[0],
    group =
      { site: "sites", ip: "ips", asn: "networks", incident: "incidents" }[
        route
      ] || route;
  document
    .querySelectorAll("nav a")
    .forEach((a) => a.classList.toggle("active", a.dataset.page === group));
}
function rangeControl(parent) {
  const bar = node("div", null, "toolbar"),
    label = node("label", "Range"),
    select = node("select");
  for (const r of ["1m", "5m", "15m", "1h", "6h", "24h", "7d"]) {
    const o = node("option", r);
    o.value = r;
    select.append(o);
  }
  select.value = range;
  select.addEventListener("change", () => {
    range = select.value;
    render();
  });
  append(bar, label, select);
  parent.append(bar);
}
function query(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== "" && v !== undefined && v !== null) q.set(k, v);
  });
  return q.toString();
}

function chart(samples, keys, labels) {
  const shell = node("div"),
    svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 600 205");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", labels.join(" and ") + " history");
  svg.classList.add("chart");
  for (let i = 0; i < 4; i++) {
    const line = document.createElementNS(svg.namespaceURI, "line");
    line.setAttribute("x1", "38");
    line.setAttribute("x2", "590");
    line.setAttribute("y1", String(20 + i * 50));
    line.setAttribute("y2", String(20 + i * 50));
    svg.append(line);
  }
  keys.forEach((key, index) => {
    const max = Math.max(
      1,
      ...samples
        .filter((s) => !s.missing && s[key] !== null && s[key] !== undefined)
        .map((s) => Number(s[key])),
    );
    let points = [];
    const draw = () => {
      if (points.length) {
        const line = document.createElementNS(svg.namespaceURI, "polyline");
        line.setAttribute("class", index ? "second" : "");
        line.setAttribute("points", points.join(" "));
        svg.append(line);
        points = [];
      }
    };
    samples.forEach((s, i) => {
      if (s.missing || s[key] === null || s[key] === undefined) {
        draw();
        return;
      }
      points.push(
        `${38 + (i / Math.max(samples.length - 1, 1)) * 552},${173 - (145 * Number(s[key])) / max}`,
      );
    });
    draw();
  });
  const legend = node("div", null, "legend");
  labels.forEach((label, i) => {
    const item = node("span");
    append(
      item,
      node("i", null, "swatch" + (i ? " second" : "")),
      document.createTextNode(label),
    );
    legend.append(item);
  });
  shell.append(svg, legend);
  return shell;
}

function incidentRows(items) {
  return (items || []).map((item) => {
    const i = item.incident || item;
    return [
      link(i.client_ip || "—", `#ip/${encodeURIComponent(i.client_ip || "")}`),
      i.site_id
        ? link(i.site_id, `#site/${encodeURIComponent(i.site_id)}`)
        : "All sites",
      fmt(i.score),
      badge(i.decision),
      when(i.timestamp),
      (i.signals || []).map((s) => s.code).join(", ") || "—",
      item.id ? link("Details", `#incident/${item.id}`) : "—",
    ];
  });
}
function recentPanel(items) {
  const p = panel("Recent incidents");
  p.append(
    table(
      ["IP", "Site", "Score", "Decision", "Time", "Signals", ""],
      incidentRows(items),
      "incident-table",
    ),
  );
  if (!items || !items.length)
    p.append(note("No recent incidents in this selection."));
  return p;
}

async function overview(generation, background) {
  setTitle("Overview");
  const next = node("div");
  if (
    !overviewCache ||
    overviewCache.range !== range ||
    Date.now() - overviewCachedAt > 30000
  ) {
    const response = await Promise.all([
      api("stats?range=" + range),
      api("server"),
      api("incidents?limit=8"),
    ]);
    // Ignore an earlier request after a refresh, live update, or navigation.
    if (generation !== renderGeneration || current() !== "overview") return;
    overviewCache = {
      range,
      stats: response[0],
      server: response[1],
      incidents: response[2],
    };
    overviewCachedAt = Date.now();
  }
  if (generation !== renderGeneration || current() !== "overview") return;
  const errorsPanel = await errorContext();
  if (generation !== renderGeneration || current() !== "overview") return;
  const { stats, server, incidents } = overviewCache;
  if (lastLive) {
    stats.live = lastLive.live;
    server.health = lastLive.health;
    server.php_fpm = lastLive.php_fpm;
    server.analysis_active = lastLive.analysis_active;
    server.recent_incident_summary = lastLive.recent_incident_summary;
  }
  serverName.textContent = server.name || "ReqSentry";
  const v = stats.live,
    h = server.health || {},
    pools = server.php_fpm || [],
    summary = server.recent_incident_summary || {};
  const bucketLabel =
    (stats.history?.[0]?.bucket_minutes || 1) === 1
      ? "minute"
      : `${stats.history[0].bucket_minutes}-minute bucket`;
  const values = overviewValues(v, h, pools, summary, server.name, server.analysis_active);
  const cards = node("div", null, "grid metrics");
  append(cards, ...values.metrics.map(value => metric(...value)));
  next.append(cards);
  const split = node("div", null, "split");
  const graph = panel("Traffic and server load");
  if (stats.history?.length) {
    graph.append(
      chart(
        stats.history,
        ["requests", "status_404"],
        [`Requests / ${bucketLabel}`, `404 / ${bucketLabel}`],
      ),
    );
    graph.append(
      note(
        "Each series is scaled to its own peak. Incomplete or absent buckets appear as gaps.",
      ),
    );
  } else
    graph.append(empty("History appears after the first complete minute."));
  const status = panel("System state");
  append(status, ...values.state.map(value => kv(...value)));
  append(split, graph, status);
  next.append(split);
  if (stats.history?.length) {
    const impact = panel("Error and resource trends");
    impact.append(
      chart(
        stats.history,
        ["status_5xx", "cpu_percent"],
        [`5xx / ${bucketLabel}`, "CPU %"],
      ),
      note(
        "Each series uses its own peak; missing health samples appear as gaps.",
      ),
    );
    next.append(impact);
    const incidentsChart = panel("Traffic and incidents");
    incidentsChart.append(
      chart(
        stats.history,
        ["requests", "incidents"],
        [`Requests / ${bucketLabel}`, `Stored incidents / ${bucketLabel}`],
      ),
      note(
        "Incident gaps mean the SQLite count was unavailable when the bucket was saved.",
      ),
    );
    next.append(incidentsChart);
  }
  next.append(
    recentPanel(incidents.incidents),
    errorsPanel,
    note(stats.coverage),
    note(summary.coverage || ""),
  );
  // An input may have gained focus while the background requests were pending.
  if (background && overviewVisible() && root.contains(document.activeElement) &&
      document.activeElement.matches("input, select, button")) return;
  // Commit a complete view in one synchronous update, never an empty page.
  root.replaceChildren(...next.childNodes);
  overviewView = {cards, state: [...status.querySelectorAll(".kv")]};
  overviewRetryAt = 0;
}

async function sites(view) {
  setTitle("Sites");
  clear(view);
  const data = await api("sites"),
    p = panel("Monitored sites"),
    bar = node("div", null, "toolbar"),
    select = node("select");
  [
    "requests",
    "site",
    "404 rate",
    "active IPs",
    "suspicious",
    "would block",
    "incidents",
  ].forEach((v) => {
    const o = node("option", v);
    o.value = v;
    select.append(o);
  });
  bar.append(node("label", "Sort by"), select);
  p.append(bar);
  const renderRows = () => {
    const sites = [...(data.sites || [])];
    sites.sort((a, b) =>
      select.value === "site"
        ? a.site_id.localeCompare(b.site_id)
        : select.value === "404 rate"
          ? (b.statuses?.[404] || 0) / Math.max(1, b.requests) -
            (a.statuses?.[404] || 0) / Math.max(1, a.requests)
          : select.value === "active IPs"
            ? b.active_ips - a.active_ips
            : select.value === "suspicious"
              ? b.suspicious_ips - a.suspicious_ips
              : select.value === "would block"
                ? b.would_block_ips - a.would_block_ips
                : select.value === "incidents"
                  ? b.recent_incidents - a.recent_incidents
                  : b.requests - a.requests,
    );
    const old = p.querySelector(".tablewrap");
    if (old) old.remove();
    p.append(
      table(
        [
          "Site",
          "Requests / min",
          "404 rate",
          "5xx rate",
          "Active IPs",
          "Suspicious",
          "Would block",
          "Incidents",
        ],
        sites.map((s) => [
          link(
            s.site_id || "(default)",
            `#site/${encodeURIComponent(s.site_id)}`,
          ),
          fmt(s.requests),
          pct(s.statuses?.[404] || 0, s.requests),
          pct(s.status_families?.[5] || 0, s.requests),
          fmt(s.active_ips),
          fmt(s.suspicious_ips),
          fmt(s.would_block_ips),
          fmt(s.recent_incidents),
        ]),
      ),
    );
  };
  select.addEventListener("change", renderRows);
  renderRows();
  view.append(
    p,
    note(
      "Traffic covers the rolling minute. Incident counts cover at most 100 recent saved decisions in memory over five minutes. Select a site for details.",
    ),
  );
}
async function siteDetail(site, view) {
  setTitle("Site details");
  clear(view);
  const d = await api("sites/" + encodeURIComponent(site) + "?range=" + range),
    s = d.site;
  view.append(node("h2", s.site_id || "Default site"));
  rangeControl(view);
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric("Requests", fmt(s.requests), "rolling minute"),
    metric("Active IPs", fmt(s.active_ips), "tracked clients"),
    metric(
      "404 rate",
      pct(s.statuses?.[404] || 0, s.requests),
      fmt(s.statuses?.[404] || 0) + " responses",
    ),
    metric(
      "5xx rate",
      pct(s.status_families?.[5] || 0, s.requests),
      "rolling minute",
    ),
    metric("Incidents", fmt(d.incident_count_24h), "last 24 hours"),
  );
  view.append(cards);
  const pair = node("div", null, "grid two"),
    methods = panel("Methods"),
    statuses = panel("Response codes");
  methods.append(
    table(
      ["Method", "Requests"],
      Object.entries(s.methods || {})
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => [k, fmt(v)]),
    ),
  );
  statuses.append(
    table(
      ["Status", "Responses"],
      Object.entries(s.statuses || {})
        .sort((a, b) => b[1] - a[1])
        .map(([k, v]) => [k, fmt(v)]),
    ),
  );
  append(pair, methods, statuses);
  view.append(pair);
  const ips = panel("Top tracked IPs");
  ips.append(
    table(
      ["IP", "Requests", "Peak RPS", "404", "Sample paths", "Evidence"],
      (d.top_ips || []).map((i) => [
        link(
          i.ip,
          "#ip/" +
            encodeURIComponent(i.ip) +
            "?site=" +
            encodeURIComponent(site),
        ),
        fmt(i.requests),
        fmt(i.peak_rps),
        fmt(i.status_404),
        i.path_samples?.join(", ") || "—",
        Object.entries(i.saturation || {})
          .filter(([, value]) => value === true)
          .map(([key]) => key)
          .join(", ") || "No per-IP saturation flag",
      ]),
    ),
  );
  view.append(ips);
  const networksPanel = panel("Sampled networks");
  networksPanel.append(
    table(
      ["ASN", "Organization", "Tracked IPs", "Sampled requests"],
      (d.top_networks || []).map((n) => [
        link("AS" + n.asn, "#asn/" + n.asn),
        n.organization || "—",
        fmt(n.tracked_ips),
        fmt(n.sampled_requests),
      ]),
    ),
  );
  view.append(networksPanel);
  const sampleGrid = node("div", null, "grid two");
  for (const [heading, key] of [
    ["Requested path samples", "paths"],
    ["404 path samples", "missing_paths"],
    ["Query pattern samples", "query_patterns"],
    ["User-Agent samples", "user_agents"],
  ]) {
    const p = panel(heading);
    p.append(
      table(
        ["Sample", "Tracked IPs"],
        Object.entries(d.samples?.[key] || {})
          .sort((a, b) => b[1] - a[1])
          .slice(0, 20)
          .map(([name, count]) => [name, fmt(count)]),
      ),
    );
    sampleGrid.append(p);
  }
  view.append(sampleGrid);
  if (d.history?.length) {
    const minutes = d.history[0].bucket_minutes || 1,
      g = panel("Traffic history");
    g.append(
      chart(
        d.history,
        ["requests", "status_404"],
        [`Requests / ${minutes}m bucket`, `404 / ${minutes}m bucket`],
      ),
      note("Incomplete or absent buckets appear as gaps."),
    );
    view.append(g);
  }
  view.append(link("Search incident logs for this site", "#logs/"+encodeURIComponent(site)), await errorContext(site), recentPanel(d.recent_incidents || []), note(d.sample_coverage));
}

async function ips(view) {
  setTitle("IP explorer");
  clear(view);
  const bar = node("div", null, "toolbar"),
    input = node("input"),
    button = node("button", "Inspect IP");
  input.placeholder = "IPv4 or IPv6";
  input.setAttribute("aria-label", "IP address");
  button.addEventListener("click", () => {
    if (input.value.trim())
      location.hash = "ip/" + encodeURIComponent(input.value.trim());
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") button.click();
  });
  append(bar, input, button);
  view.append(bar);
  const d = await api("ips?limit=50"),
    p = panel("Top tracked IPs");
  p.append(
    table(
      ["IP", "Requests", "Peak RPS", "404", "Sites"],
      (d.ips || []).map((i) => [
        link(i.ip, "#ip/" + encodeURIComponent(i.ip)),
        fmt(i.requests),
        fmt(i.peak_rps),
        fmt(i.status_404),
        siteLinks(i.site_ids),
      ]),
    ),
  );
  view.append(
    p,
    note(
      d.sample_coverage +
        " Site names show where each tracked IP had traffic in the rolling minute.",
    ),
  );
}
async function ipDetail(rest, view) {
  setTitle("IP investigation");
  clear(view);
  const [encodedIP, qs] = rest.split("?"),
    ip = decodeURIComponent(encodedIP),
    params = new URLSearchParams(qs || "");
  const d = await api(
      "ips/" +
        encodeURIComponent(ip) +
        "?" +
        query({ site: params.get("site") || "" }),
    ),
    s = d.snapshot,
    e = d.enrichment || {},
    latest = d.recent_incidents?.[0]?.incident;
  view.append(node("h2", ip, "mono"));
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric("Requests", fmt(s.Requests), "rolling minute"),
    metric("Peak RPS", fmt(s.PeakRPS), "rolling minute"),
    metric(
      "404",
      fmt(s.ImportantStatuses?.[404] || 0),
      pct(s.ImportantStatuses?.[404] || 0, s.Requests),
    ),
    metric("Previous incidents", fmt(d.incident_count_7d), "last 7 days"),
    metric(
      "Last saved score",
      latest ? fmt(latest.score) + " / 100" : "—",
      latest ? when(latest.timestamp) : "No incident",
    ),
    metric(
      "Last saved decision",
      latest?.decision || "—",
      "Historical · monitor only",
    ),
  );
  view.append(cards);
  const pair = node("div", null, "grid two"),
    network = panel("Network"),
    pattern = panel("Request patterns");
  append(
    network,
    kv("ASN", e.ASN ? link("AS" + e.ASN, "#asn/" + e.ASN) : "Unavailable"),
    kv("Organization", e.ASNOrganization || "—"),
    kv("Type", e.NetworkType || "—"),
    kv("Country", e.Country || "—"),
    kv("Enrichment", d.enrichment_available ? "Available" : "Unavailable"),
  );
  append(
    pattern,
    kv("Unique paths", fmt(s.UniquePaths)),
    kv("Unique 404 paths", fmt(s.Unique404Paths)),
    kv("Query patterns", fmt(s.QueryPatterns)),
    kv("Sample paths", (s.PathSamples || []).join(", ") || "—"),
    kv("404 path samples", (s.MissingPathSamples || []).join(", ") || "—"),
    kv("Query samples", (s.QueryPatternSamples || []).join(", ") || "—"),
  );
  append(pair, network, pattern);
  view.append(pair);
  if (latest) {
    const detected = panel("Signals in last saved incident");
    detected.append(
      node(
        "div",
        (latest.signals || []).map((x) => x.code).join(", ") || "No signals",
        "pills",
      ),
      note(
        "Historical detector evidence from " +
          when(latest.timestamp) +
          "; open the incident for weights and context.",
      ),
    );
    view.append(detected);
  }
  const methods = panel("Methods and responses");
  methods.append(
    table(
      ["Method", "Requests", "404"],
      Object.entries(s.Methods || {}).map(([method, n]) => [
        method,
        fmt(n),
        fmt(s.Method404?.[method] || 0),
      ]),
    ),
  );
  view.append(
    methods,
    recentPanel(d.recent_incidents || []),
    note(
      "Current values are from the detector's tracked client window. Sample paths and agents are bounded evidence, not request totals.",
    ),
  );
}

async function networks(view) {
  setTitle("Networks");
  clear(view);
  const d = await api("asns?limit=50"),
    p = panel("Top sampled networks");
  p.append(
    table(
      [
        "ASN",
        "Organization",
        "Type",
        "Tracked IPs",
        "Sampled requests",
        "Sampled 404",
      ],
      (d.networks || []).map((n) => [
        link("AS" + n.asn, "#asn/" + n.asn),
        n.organization || "—",
        n.network_type || "—",
        fmt(n.tracked_ips),
        fmt(n.sampled_requests),
        fmt(n.sampled_404),
      ]),
    ),
  );
  view.append(
    p,
    note(d.sample_coverage),
    note(
      "A network is not classified as malicious based on a client's activity.",
    ),
  );
}
async function networkDetail(asn, view) {
  setTitle("Network details");
  clear(view);
  const n = await api("asns/" + encodeURIComponent(asn)),
    p = panel(
      "AS" + n.asn + " · " + (n.organization || "Unknown organization"),
    );
  append(
    p,
    kv("Network type", n.network_type || "—"),
    kv("Country", n.country || "—"),
    kv("Tracked IPs", fmt(n.tracked_ips)),
    kv("Sampled requests", fmt(n.sampled_requests)),
    kv("Sampled 404", fmt(n.sampled_404)),
    kv("Sampled 404 rate", pct(n.sampled_404, n.sampled_requests)),
    kv("Recent incidents", fmt(n.recent_incident_count)),
    kv("Suspicious IPs in recent incidents", fmt(n.recent_suspicious_ips)),
    kv("Would-block IPs in recent incidents", fmt(n.recent_would_block_ips)),
    kv("Recent sites", (n.recent_sites || []).join(", ") || "—"),
  );
  view.append(p);
  const ipsPanel = panel("Observed IPs");
  ipsPanel.append(
    table(
      ["IP", "Requests", "404"],
      (n.ips || []).map((i) => [
        link(i.ip, "#ip/" + encodeURIComponent(i.ip)),
        fmt(i.requests),
        fmt(i.status_404),
      ]),
    ),
  );
  view.append(
    ipsPanel,
    note(
      "This view covers bounded tracked IP samples and at most 100 recent in-memory incidents, not all traffic on the ASN.",
    ),
  );
}

async function httpAnalytics(view) {
  setTitle("HTTP analytics");
  clear(view);
  const [stats, agents] = await Promise.all([
      api("stats?range=1m"),
      api("user-agents"),
    ]),
    v = stats.live;
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric(
      "2xx",
      pct(v.status_families?.[2] || 0, v.requests),
      fmt(v.status_families?.[2] || 0) + " responses",
    ),
    metric("301", fmt(v.statuses?.[301] || 0), "redirects"),
    metric("302", fmt(v.statuses?.[302] || 0), "redirects"),
    metric("403", fmt(v.statuses?.[403] || 0), "forbidden"),
    metric(
      "404",
      pct(v.statuses?.[404] || 0, v.requests),
      fmt(v.statuses?.[404] || 0) + " responses",
      "warn",
    ),
    metric(
      "5xx",
      pct(v.status_families?.[5] || 0, v.requests),
      fmt(v.status_families?.[5] || 0) + " responses",
      "warn",
    ),
    metric(
      "Missing User-Agent",
      fmt(agents.sampled_missing_user_agent_requests),
      "top tracked IP sample",
    ),
  );
  view.append(cards);
  const pair = node("div", null, "grid two"),
    methods = panel("Methods"),
    statuses = panel("Statuses");
  methods.append(
    table(
      ["Method", "Requests", "2xx", "301", "302", "403", "404", "5xx"],
      Object.entries(v.method_http || {})
        .sort((a, b) => b[1].requests - a[1].requests)
        .map(([k, row]) => [
          k,
          fmt(row.requests),
          fmt(row.status_2xx),
          fmt(row.status_301),
          fmt(row.status_302),
          fmt(row.status_403),
          fmt(row.status_404),
          fmt(row.status_5xx),
        ]),
    ),
  );
  statuses.append(
    table(
      ["Status", "Responses"],
      Object.entries(v.statuses || {})
        .sort((a, b) => b[1] - a[1])
        .map(([k, n]) => [k, fmt(n)]),
    ),
  );
  append(pair, methods, statuses);
  view.append(pair);
  const ips = panel("Most 404s among tracked IPs");
  ips.append(
    table(
      ["IP", "404", "Unique 404 paths", "Requests", "Sample 404 paths"],
      [...(v.top_ips || [])]
        .sort((a, b) => b.status_404 - a.status_404)
        .slice(0, 20)
        .map((i) => [
          link(i.ip, "#ip/" + encodeURIComponent(i.ip)),
          fmt(i.status_404),
          fmt(i.unique_404_paths),
          fmt(i.requests),
          (i.missing_path_samples || []).join(", ") || "—",
        ]),
    ),
  );
  view.append(ips);
  const samples = { paths: {}, missing: {}, query: {} };
  for (const item of v.top_ips || []) {
    for (const [field, key] of [
      ["path_samples", "paths"],
      ["missing_path_samples", "missing"],
      ["query_patterns", "query"],
    ])
      for (const value of item[field] || [])
        samples[key][value] = (samples[key][value] || 0) + 1;
  }
  const sampleGrid = node("div", null, "grid three");
  for (const [heading, key] of [
    ["Requested path samples", "paths"],
    ["404 path samples", "missing"],
    ["Normalized query samples", "query"],
  ]) {
    const p = panel(heading);
    p.append(
      table(
        ["Sample", "Tracked IPs"],
        Object.entries(samples[key])
          .sort((a, b) => b[1] - a[1])
          .slice(0, 20)
          .map(([name, count]) => [name, fmt(count)]),
      ),
    );
    sampleGrid.append(p);
  }
  view.append(sampleGrid);
  const agentsPanel = panel("User-Agent samples");
  agentsPanel.append(
    table(
      [
        "User-Agent",
        "Sampled requests",
        "Tracked IPs",
        "IPs with recent suspicious incident",
        "IPs with recent would-block incident",
      ],
      Object.entries(agents.agents || {})
        .sort((a, b) => b[1].sampled_requests - a[1].sampled_requests)
        .map(([name, item]) => [
          name,
          fmt(item.sampled_requests),
          fmt(item.tracked_ips),
          fmt(item.recent_suspicious_ips),
          fmt(item.recent_would_block_ips),
        ]),
    ),
  );
  view.append(
    agentsPanel,
    note(
      agents.sample_coverage +
        " User-Agent strings do not prove client identity.",
    ),
  );
}

async function health(view) {
  setTitle("Server health");
  clear(view);
  rangeControl(view);
  const [server, stats] = await Promise.all([
      api("server"),
      api("stats?range=" + range),
    ]),
    h = server.health || {},
    pools = server.php_fpm || [];
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric(
      "CPU",
      h.CPUPercent === undefined || h.CPUPercent === null
        ? "—"
        : h.CPUPercent.toFixed(1) + "%",
      when(h.Timestamp),
    ),
    metric(
      "Memory",
      h.MemoryUsedPercent === undefined || h.MemoryUsedPercent === null
        ? "—"
        : h.MemoryUsedPercent.toFixed(1) + "%",
      "latest sample",
    ),
    metric(
      "Load 1m",
      h.Load1 === undefined || h.Load1 === null
        ? "—"
        : Number(h.Load1).toFixed(2),
      "system load",
    ),
    metric(
      "Load 5m / 15m",
      [h.Load5, h.Load15]
        .map((v) =>
          v === undefined || v === null ? "—" : Number(v).toFixed(2),
        )
        .join(" / "),
      "system load",
    ),
  );
  view.append(cards);
  if (stats.history?.length) {
    for (const [heading, first, second, labels] of [
      [
        "Traffic and CPU history",
        "requests",
        "cpu_percent",
        ["Requests / minute", "CPU %"],
      ],
      [
        "Traffic and PHP-FPM history",
        "requests",
        "php_active",
        ["Requests / minute", "Active workers"],
      ],
      [
        "Traffic and system load",
        "requests",
        "load_1m",
        ["Requests / minute", "Load 1m"],
      ],
    ]) {
      const p = panel(heading);
      p.append(
        chart(stats.history, [first, second], labels),
        note("Each series uses its own peak. Missing samples appear as gaps."),
      );
      view.append(p);
    }
  }
  const p = panel("PHP-FPM pools");
  p.append(
    table(
      [
        "Pool",
        "State",
        "Active",
        "Idle",
        "Total",
        "Max active",
        "Max children reached",
        "Slow requests",
        "Queue",
        "Sampled",
      ],
      pools.map((x) => [
        x.Name,
        x.Stale ? "Stale" : "Current",
        fmt(x.Stats?.["active processes"]),
        fmt(x.Stats?.["idle processes"]),
        fmt(x.Stats?.["total processes"]),
        fmt(x.Stats?.["max active processes"]),
        fmt(x.Stats?.["max children reached"]),
        fmt(x.Stats?.["slow requests"]),
        fmt(x.Stats?.["listen queue"]),
        when(x.SampledAt),
      ]),
    ),
  );
  view.append(
    p,
    note(
      "Missing measurements remain unavailable; stale PHP-FPM samples are labeled.",
    ),
  );
}

async function phpfpmPage(view) {
  setTitle("PHP-FPM");
  clear(view);
  rangeControl(view);
  const [data, stats] = await Promise.all([
      api("phpfpm"),
      api("stats?range=" + range),
    ]),
    pools = data.pools || [];
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric(
      "Active workers",
      fmt(
        pools.reduce(
          (n, p) => n + Number(p.Stats?.["active processes"] || 0),
          0,
        ),
      ),
      "all available pools",
    ),
    metric(
      "Idle workers",
      fmt(
        pools.reduce((n, p) => n + Number(p.Stats?.["idle processes"] || 0), 0),
      ),
      "all available pools",
    ),
    metric(
      "Stale pools",
      fmt(pools.filter((p) => p.Stale).length),
      "check collector errors",
    ),
    metric(
      "Max children events",
      fmt(
        pools.reduce(
          (n, p) => n + Number(p.Stats?.["max children reached"] || 0),
          0,
        ),
      ),
      "reported by PHP-FPM",
    ),
  );
  view.append(cards);
  if (stats.history?.length) {
    const p = panel("Requests and active workers");
    p.append(
      chart(
        stats.history,
        ["requests", "php_active"],
        ["Requests / minute", "Active workers"],
      ),
      note("Each series uses its own peak. Missing samples appear as gaps."),
    );
    view.append(p);
  }
  const p = panel("Pool details");
  p.append(
    table(
      [
        "Pool",
        "State",
        "Active",
        "Idle",
        "Total",
        "Max active",
        "Max children reached",
        "Slow requests",
        "Queue",
        "Sampled",
      ],
      pools.map((x) => [
        x.Name,
        x.Stale ? "Stale" : "Current",
        fmt(x.Stats?.["active processes"]),
        fmt(x.Stats?.["idle processes"]),
        fmt(x.Stats?.["total processes"]),
        fmt(x.Stats?.["max active processes"]),
        fmt(x.Stats?.["max children reached"]),
        fmt(x.Stats?.["slow requests"]),
        fmt(x.Stats?.["listen queue"]),
        when(x.SampledAt),
      ]),
    ),
  );
  view.append(
    p,
    note(
      "PHP-FPM is optional. A missing or stale sample is never treated as zero.",
    ),
  );
}

async function incidents(view) {
  setTitle("Incidents");
  clear(view);
  const filters = node("div", null, "toolbar");
  const fields = [
      ["Site", "site"],
      ["Server", "server"],
      ["IP", "ip"],
      ["Request sample text", "q"],
      ["Signal", "signal"],
      ["Min score", "min_score"],
    ],
    inputs = {};
  fields.forEach(([label, key]) => {
    const i = node("input");
    i.placeholder = label;
    i.setAttribute("aria-label", label);
    i.value = incidentFilter[key];
    inputs[key] = i;
    filters.append(i);
  });
  for (const key of ["from", "to"]) {
    const label = node("label", key === "from" ? "From" : "To"),
      i = node("input");
    i.type = "datetime-local";
    i.setAttribute("aria-label", key + " time");
    i.value = incidentFilter[key];
    inputs[key] = i;
    append(filters, label, i);
  }
  const decision = node("select");
  ["", "WATCH", "SUSPICIOUS", "WOULD_BLOCK", "NORMAL"].forEach((x) => {
    const o = node("option", x || "Any decision");
    o.value = x;
    decision.append(o);
  });
  decision.value = incidentFilter.decision;
  filters.append(decision);
  const search = node("button", "Search");
  search.addEventListener("click", () => {
    Object.keys(inputs).forEach(
      (k) => (incidentFilter[k] = inputs[k].value.trim()),
    );
    incidentFilter.decision = decision.value;
    incidentPage = 1;
    render();
  });
  filters.append(search);
  view.append(filters);
  const apiFilter = { ...incidentFilter };
  for (const key of ["from", "to"]) {
    if (apiFilter[key]) apiFilter[key] = new Date(apiFilter[key]).toISOString();
  }
  const d = await api(
    "incidents?" + query({ ...apiFilter, page: incidentPage, limit: 20 }),
  );
  const p = panel(`Incidents · ${fmt(d.total)} matches`);
  p.append(
    table(
      ["IP", "Site", "Score", "Decision", "Time", "Signals", ""],
      incidentRows(d.incidents),
      "incident-table",
    ),
  );
  if (!d.incidents.length)
    p.append(empty("No incidents in this time range match these filters."));
  view.append(p);
  const pages = node("div", null, "toolbar"),
    prev = node("button", "Previous"),
    next = node("button", "Next");
  prev.disabled = incidentPage <= 1;
  next.disabled = !d.next_page;
  prev.addEventListener("click", () => {
    incidentPage--;
    render();
  });
  next.addEventListener("click", () => {
    incidentPage++;
    render();
  });
  append(pages, prev, node("span", `Page ${incidentPage}`), next);
  view.append(
    pages,
    note(
      "Scores and signal evidence are stored at detection time; historical incidents are not rescored.",
    ),
  );
}
async function errorContext(site = "") {
  const p = panel("Observed errors");
  const filters = node("div", null, "error-filters");
  const severity = node("select");
  for (const value of ["", "warning", "error", "critical", "alert", "emergency"]) {
    const option = node("option", value || "All severities");
    option.value = value;
    severity.append(option);
  }
  severity.value = errorSeverity;
  severity.setAttribute("aria-label", "Error severity");
  severity.onchange = () => { errorSeverity = severity.value; render(); };
  const association = node("select");
  for (const value of ["", "request_id", "trace_id", "logged_client_path_time", "site_time", "server_time"]) {
    const option = node("option", value ? value.replaceAll("_", " ") : "All associations");
    option.value = value;
    association.append(option);
  }
  association.value = errorAssociation;
  association.setAttribute("aria-label", "Error association");
  association.onchange = () => { errorAssociation = association.value; render(); };
  const category = node("input");
  category.value = errorCategory;
  category.placeholder = "Category (exact match)";
  category.maxLength = 128;
  category.setAttribute("aria-label", "Error category");
  category.onchange = () => { errorCategory = category.value.trim(); render(); };
  filters.append(severity, association, category);
  p.append(filters);
  try {
    const d = await api("errors?" + query({site, range, severity: errorSeverity, association: errorAssociation, category: errorCategory, limit: 20}));
    p.append(note(d.coverage));
    if ((d.timeline || []).length) p.append(chart(d.timeline, ["errors"], ["Persisted error samples"]), note(`Timeline covers all severities in ${d.bucket_seconds}-second buckets with saved samples. Empty intervals may lack data.`));
    p.append(table(["Time", "Site", "Severity", "Category", "Message"], (d.errors || []).map(e => [when(e.timestamp), e.site_id || "Server", e.severity, e.category, e.message]), "error-table"));
    if (!(d.errors || []).length) p.append(note((d.sources || []).length ? "No errors observed in this selection; inspect source availability." : "No error source configured."));
    for (const id of d.related_incidents || []) p.append(link("Related saved incident " + id, "#incident/" + id));
    for (const src of d.sources || []) {
      const counts = `${fmt(src.Parsed)} parsed · ${fmt(src.BadLines)} malformed · ${fmt(src.Filtered)} filtered`;
      const last = src.LastRecordAt && new Date(src.LastRecordAt).getFullYear() > 1 ? ` · last record ${when(src.LastRecordAt)}` : " · no record observed";
      p.append(kv(src.Site || "Server", src.Open && !src.LastError ? counts + last : "Source unavailable"));
    }
  } catch { p.append(note("Error context unavailable.")); }
  return p;
}
function errorCounts(values) {
  return Object.entries(values || {}).map(([key, count]) => `${key.replaceAll("_", " ")}: ${fmt(count)}`).join(" · ") || "None observed";
}
function errorSource(event) {
  const source = event.source || "";
  const label = node("span", source.split("/").pop() || event.site_id || "Server");
  label.title = source;
  return label;
}
async function incidentDetail(id, view) {
  setTitle("Incident details");
  clear(view);
  const d = await api("incidents/" + encodeURIComponent(id)),
    i = d.incident;
  const cards = node("div", null, "grid metrics");
  append(
    cards,
    metric("Score", fmt(i.score) + " / 100", "raw " + fmt(i.raw_score)),
    metric("Decision", i.decision, "No enforcement action was taken"),
    metric("Requests", fmt(i.requests), "detection window"),
    metric("Peak RPS", fmt(i.peak_rps), "detection window"),
  );
  view.append(cards);
  const p = panel("Saved evidence and context");
  append(
    p,
    kv("IP", link(i.client_ip, "#ip/" + encodeURIComponent(i.client_ip))),
    kv(
      "Site",
      i.site_id
        ? link(i.site_id, "#site/" + encodeURIComponent(i.site_id))
        : "All sites",
    ),
    kv("Detected", when(i.timestamp)),
    kv("Window", when(i.window_start) + " — " + when(i.window_end)),
    kv("Ruleset version", fmt(i.ruleset_version)),
    kv("Enrichment", i.enrichment_status || "—"),
    kv("ASN", i.asn ? link("AS" + i.asn, "#asn/" + i.asn) : "—"),
    kv("Organization", i.asn_organization || "—"),
  );
  view.append(p);
  const samples = panel("Sample requests");
  samples.append(note("Up to five requests saved from this incident window. Query strings and raw log lines are omitted."));
  if ((i.request_samples || []).length) samples.append(requestSampleTable(i.request_samples.map(sample => ({sample, incident_id:d.id, server:i.server, score:i.score}))));
  else samples.append(empty("Request samples are unavailable for this incident."));
  samples.append(link("Search incident logs for this site", "#logs/" + encodeURIComponent(i.site_id || "")));
  view.append(samples);
  const signals = panel("Detector signals");
  (i.signals || []).forEach((s) => {
    const x = node("div", null, "kv");
    append(
      x,
      badge(s.code),
      node(
        "span",
        `${s.strength} · weight ${s.weight} · ${JSON.stringify(s.evidence || {})}`,
      ),
    );
    signals.append(x);
  });
  view.append(signals);
  const response = panel("HTTP and server impact");
  append(
    response,
    kv("404", fmt(i.status_counts?.[404] || 0)),
    kv("Unique 404 paths", fmt(i.unique_404_paths)),
    kv(
      "CPU",
      i.cpu_percent === null || i.cpu_percent === undefined
        ? "—"
        : i.cpu_percent + "%",
    ),
    kv(
      "Load 1m",
      i.load_1 === null || i.load_1 === undefined
        ? "—"
        : Number(i.load_1).toFixed(2),
    ),
    kv(
      "Memory",
      i.memory_used_percent === null || i.memory_used_percent === undefined
        ? "—"
        : i.memory_used_percent + "%",
    ),
    kv(
      "Traffic share",
      i.traffic_share === null || i.traffic_share === undefined
        ? "—"
        : pct(i.traffic_share, 1),
    ),
    kv("Evidence incomplete", (i.evidence_incomplete || []).join(", ") || "No"),
  );
  view.append(response);
  const errorPanel = panel("Saved error correlation");
  if (!i.errors) errorPanel.append(note("Error context unavailable for this historical incident."));
  else {
    errorPanel.append(kv("Observed errors", fmt(i.errors.observed)), note(i.errors.coverage || "Bounded evidence"), kv("Categories", errorCounts(i.errors.categories)), kv("Associations", errorCounts(i.errors.associations)), kv("Dropped evidence", fmt(i.errors.dropped)), kv("Unavailable sources", (i.errors.unavailable_sources || []).join(", ") || "None reported"));
    errorPanel.append(table(["Time", "Source", "Category", "Association", "Message"], (i.errors.samples || []).map(x => [when(x.event.timestamp), errorSource(x.event), x.event.category, x.method.replaceAll("_", " ") + (x.uncertain ? " (uncertain)" : " (shared log ID)"), x.event.message]), "error-table"));
    errorPanel.append(note("An association is evidence to inspect; it does not prove that the client caused a failure."));
  }
  view.append(errorPanel);
  if (i.php_fpm?.length) {
    const php = panel("Saved PHP-FPM state");
    php.append(
      table(
        [
          "Pool",
          "Active",
          "Idle",
          "Total",
          "Max children reached",
          "Slow requests",
          "Queue",
          "Stale",
        ],
        i.php_fpm.map((x) => [
          x.name,
          fmt(x.active_processes),
          fmt(x.idle_processes),
          fmt(x.total_processes),
          fmt(x.max_children_reached),
          fmt(x.slow_requests),
          fmt(x.listen_queue),
          x.stale ? "Yes" : "No",
        ]),
      ),
    );
    view.append(php);
  }
  view.append(
    note(
      "This is the historical detection snapshot, not the IP's current state.",
    ),
  );
}

async function render({background = false} = {}) {
  const generation = ++renderGeneration,
    route = current(),
    parts = route.split("/"),
    page = parts[0];
  const view = node("div");
  if (page === "overview") overviewPending++;
  try {
    if (page === "overview") await overview(generation, background);
    else if (page === "sites") await sites(view);
    else if (page === "site")
      await siteDetail(decodeURIComponent(parts.slice(1).join("/")), view);
    else if (page === "ips") await ips(view);
    else if (page === "ip") await ipDetail(parts.slice(1).join("/"), view);
    else if (page === "networks") await networks(view);
    else if (page === "asn") await networkDetail(parts[1], view);
    else if (page === "http") await httpAnalytics(view);
    else if (page === "health") await health(view);
    else if (page === "phpfpm") await phpfpmPage(view);
    else if (page === "logs") await requestLogs(parts.length > 1 ? decodeURIComponent(parts.slice(1).join("/")) : undefined, view);
    else if (page === "incidents") await incidents(view);
    else if (page === "incident") await incidentDetail(parts[1], view);
    else throw new Error("Unknown dashboard section");
    if (page !== "overview" && generation === renderGeneration && current() === route)
      root.replaceChildren(...view.childNodes);
  } catch (e) {
    if (generation === renderGeneration) {
      if (page === "overview" && overviewVisible()) {
        overviewRetryAt = Date.now() + 30000;
        if (!root.querySelector(".overview-error")) root.prepend(node("div",
          "History refresh unavailable. Showing previous details; live counters continue when connected.",
          "error overview-error"));
      } else error(e.message || "Dashboard data unavailable");
    }
  } finally {
    if (page === "overview") overviewPending--;
  }
}

function startStream() {
  try {
    const events = new EventSource("/api/v1/stream");
    events.addEventListener("snapshot", (e) => {
      try {
        lastLive = JSON.parse(e.data);
        serverName.textContent = lastLive.server || "ReqSentry";
        connection.textContent =
          "Live · " + new Date(lastLive.at).toLocaleTimeString();
        connection.className = "connection live";
        if (current() === "overview") refreshOverviewLive();
      } catch {}
    });
    events.onerror = () => {
      connection.textContent = "Reconnecting";
      connection.className = "connection offline";
    };
  } catch {
    connection.textContent = "Manual refresh";
    connection.className = "connection offline";
  }
}
window.addEventListener("hashchange", render);
document.getElementById("refresh").addEventListener("click", () => {
  overviewCachedAt = 0;
  overviewRetryAt = 0;
  render();
});
render();
startStream();

function requestSampleTable(items) {
 return table(["Time","Server","Site","IP","Method","Path","Status","Response time","Request ID","Incident"],items.map(x=>{
  const r=x.sample;
  return [when(r.timestamp),x.server || "—",r.site_id,link(r.client_ip,"#ip/"+encodeURIComponent(r.client_ip)),r.method,r.path,fmt(r.status),r.request_ms===undefined?"Unavailable":fmt(r.request_ms)+" ms",r.request_id||"—",link("#"+x.incident_id+" · score "+fmt(x.score),"#incident/"+x.incident_id)];
 }),"error-table");
}
async function requestLogs(site, view) {
 setTitle("Incident logs");clear(view);
 const generation=++sampleGeneration, route=current();
 if(site!==undefined && sampleRouteSite!==site) {sampleFilter.site=site;samplePage=1;}
 if(site!==undefined || current()==="logs")sampleRouteSite=site;
 const filters=node("div",null,"toolbar"),inputs={};
 for(const [key,label] of [["q","Search path, method or request ID"],["site","Site"],["server","Server"],["ip","IP"],["method","Method"],["status","HTTP status"],["from","From"],["to","To"]]) {
  const input=node("input");input.placeholder=label;input.setAttribute("aria-label",label);input.value=sampleFilter[key];if(key==="from"||key==="to")input.type="datetime-local";inputs[key]=input;input.title=label;
  if(key==="from"||key==="to")filters.append(append(node("label",label),input));else filters.append(input);
 }
 const search=node("button","Search");search.addEventListener("click",()=>{for(const key of Object.keys(inputs))sampleFilter[key]=inputs[key].value.trim();samplePage=1;render();});filters.append(search);
 view.append(note("Only requests saved with incidents appear here: up to five per incident. Ten incidents contain at most fifty samples. Overlapping incidents may include the same request."),filters);
 const filter={...sampleFilter};for(const key of ["from","to"])if(filter[key])filter[key]=new Date(filter[key]).toISOString();
 const d=await api("request-samples?"+query({...filter,page:samplePage,limit:50}));
 if(generation!==sampleGeneration || current()!==route)return;
 const p=panel("Saved requests · "+fmt(d.total)+" matches");p.append(requestSampleTable(d.samples));if(!d.samples.length)p.append(empty("No saved request samples match. Older incidents may not contain request samples."));view.append(p);
 const prev=node("button","Previous"),next=node("button","Next");prev.disabled=samplePage<=1;next.disabled=!d.next_page;prev.addEventListener("click",()=>{samplePage--;render();});next.addEventListener("click",()=>{samplePage++;render();});
 view.append(append(node("div",null,"toolbar"),prev,node("span","Page "+samplePage),next),note("Time filters use incident detection time. Without dates, this view searches the last four days, subject to configured retention."));
}
