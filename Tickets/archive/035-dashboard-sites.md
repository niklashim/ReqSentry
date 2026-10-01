# 035 — Site list and detail investigation

**Status:** Done  
**Epic:** H — Site analytics  
**Depends on:** 030, 033, 034

## Objective

Compare monitored sites and investigate traffic and suspicious behavior on one site.

## Technical description and subtasks

- Build a sortable site table with RPM, 404/5xx rates, active IPs, and incident counts.
- Build site detail with bounded status/method distribution, top IPs/ASNs/User-Agents/paths/404s, pattern samples, and recent incidents.
- Link site rows to IP and incident views.

## Implementation considerations

Preserve configured site IDs; show missing watcher/input status separately from zero traffic.

## Acceptance criteria

- All configured sites appear, including idle/missing sites; sorting and links work.
- Detail metrics match the API and expose saturation/degraded labels.

## Testing requirements

Multiple sites, idle site, malicious site ID encoding, sorting, top-N caps, and empty details.

## Documentation impact

Describe site mappings and data window.

## Security considerations

Site names are untrusted display text; no URL-derived HTML injection.

## Completion

Site table and detail include sortable traffic, recent decision samples, HTTP distributions, tracked IPs, networks, path/query/User-Agent samples, history, and incidents.
