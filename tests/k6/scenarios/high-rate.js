import { request } from '../lib/helpers.js';
import { positiveInteger } from '../lib/config.js';

const rate = positiveInteger('RATE', 20, 10000);
const duration = __ENV.DURATION || '10s';
if (!/^[1-9][0-9]*(s|m)$/.test(duration)) throw new Error('DURATION must be a positive number of seconds or minutes');

export const options = {
  scenarios: {
    high_rate: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: Math.min(50, Math.max(5, Math.ceil(rate / 20))),
      maxVUs: Math.min(500, Math.max(20, Math.ceil(rate / 2))),
    },
  },
  thresholds: { checks: ['rate==1'] },
};

export default function () {
  request('shop.example', '/product?id=42', 'high-rate', 'rate_probe', { expected: [200] });
}
