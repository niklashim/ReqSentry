import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { enumeration: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '5m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  allSites((site) => {
    for (let i = 0; i < 50; i++) {
      const id = 10000 + i;
      request(site, `/product?id=${id}`, 'enumeration', 'query_sequence', { expected: [200] });
      request(site, `/users/${id}`, 'enumeration', 'path_sequence', { expected: [404] });
    }
  });
}
