import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { methods: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '2m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
  allSites((site) => {
    for (const method of methods) {
      request(site, '/about.html', 'methods', 'valid_path', { method, expected: ['GET', 'HEAD'].includes(method) ? [200] : [405] });
      request(site, '/does-not-exist', 'methods', 'missing_path', { method, expected: [404] });
    }
  });
}
