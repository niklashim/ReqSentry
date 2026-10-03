import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { positiveInteger, SITE1_URL } from '../lib/config.js';

const trafficRate = positiveInteger('RATE', 200, 10000);
const dashboardRate = positiveInteger('DASHBOARD_RATE', 20, 1000);
const duration = __ENV.DURATION || '20s';
if (!/^[1-9][0-9]*(s|m)$/.test(duration)) throw new Error('DURATION must be a positive number of seconds or minutes');

const dashboardURL = (__ENV.DASHBOARD_URL || 'http://reqsentry-web:8090').replace(/\/$/, '');
const rejected = new Counter('dashboard_rejected_requests');
const endpoints = ['/api/v1/stats?range=1m', '/api/v1/ips?limit=50', '/api/v1/incidents?limit=20', '/api/v1/server'];

export const options = {
  scenarios: {
    attack_traffic: {
      executor: 'constant-arrival-rate', rate: trafficRate, timeUnit: '1s', duration,
      preAllocatedVUs: Math.min(100, Math.max(10, Math.ceil(trafficRate / 20))),
      maxVUs: Math.min(500, Math.max(50, Math.ceil(trafficRate / 2))), exec: 'traffic',
    },
    dashboard_reads: {
      executor: 'constant-arrival-rate', rate: dashboardRate, timeUnit: '1s', duration,
      preAllocatedVUs: Math.min(30, Math.max(5, Math.ceil(dashboardRate / 10))),
      maxVUs: Math.min(100, Math.max(20, Math.ceil(dashboardRate / 2))), exec: 'dashboard',
    },
  },
  thresholds: { checks: ['rate==1'] },
};

export function traffic() {
  const response = http.get(`${SITE1_URL}/users/stress-${__VU}-${__ITER}`, {
    headers: { Host: 'shop.example' }, tags: { name: 'GET /users/stress-*', traffic_type: 'unique_404' }, timeout: '10s',
  });
  check(response, { 'Nginx returned expected 404': (r) => r.status === 404 });
}

export function dashboard() {
  const response = http.get(dashboardURL + endpoints[__ITER % endpoints.length], {
    tags: { traffic_type: 'dashboard_read' }, timeout: '10s',
  });
  if (response.status === 503) rejected.add(1);
  check(response, { 'dashboard returned 200 or bounded overload': (r) => r.status === 200 || r.status === 503 });
}
