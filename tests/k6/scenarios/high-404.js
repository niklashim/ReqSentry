import { request } from '../lib/helpers.js';

export const options = { scenarios: { high_404: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '3m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  for (let i = 0; i < 100; i++) {
    const missing = i < 90;
    const path = missing ? `/missing/high404-${String(i).padStart(3, '0')}` : '/about.html';
    request('him.com', path, 'high-404', missing ? 'missing' : 'valid', { expected: [missing ? 404 : 200] });
  }
}
