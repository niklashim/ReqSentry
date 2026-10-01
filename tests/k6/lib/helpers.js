import http from 'k6/http';
import { check } from 'k6';
import { baseURL, sites } from './config.js';

export function request(site, path, scenario, trafficType, options = {}) {
  const method = options.method || 'GET';
  const params = {
    tags: { site, scenario, traffic_type: trafficType },
    headers: { Host: site, ...options.headers },
    timeout: '10s',
  };
  if (options.redirects !== undefined) params.redirects = options.redirects;
  const response = http.request(method, `${baseURL(site)}${path}`, options.body || null, params);
  if (options.expected) {
    check(response, { [`${scenario}: expected HTTP status`]: (r) => options.expected.includes(r.status) });
  }
  return response;
}

export function allSites(callback) {
  for (const site of sites) callback(site);
}
