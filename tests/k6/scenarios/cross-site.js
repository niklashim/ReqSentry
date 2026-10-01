import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { cross_site: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '5m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  allSites((site) => {
    for (let i = 0; i < 50; i++) {
      request(site, `/users/${20000 + i}`, 'cross-site', 'site_enumeration', { expected: [404] });
    }
  });
}
