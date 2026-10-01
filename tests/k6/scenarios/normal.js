import { sleep } from 'k6';
import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { normal: { executor: 'shared-iterations', vus: 1, iterations: 5, maxDuration: '2m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  const paths = ['/', '/about.html', '/assets/style.css', '/assets/app.js', '/assets/logo.svg'];
  allSites((site) => {
    for (const path of paths) request(site, path, 'normal', 'benign', { expected: [200] });
  });
  sleep(2);
}
