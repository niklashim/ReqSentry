import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { redirects: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '2m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  allSites((site) => {
    request(site, '/old-page', 'redirects', '301_no_follow', { redirects: 0, expected: [301] });
    request(site, '/old-page', 'redirects', '301_follow', { expected: [200] });
    request(site, '/temporary', 'redirects', '302_no_follow', { redirects: 0, expected: [302] });
    request(site, '/temporary', 'redirects', '302_follow', { expected: [200] });
  });
}
