import { allSites, request } from '../lib/helpers.js';

export const options = { scenarios: { user_agents: { executor: 'shared-iterations', vus: 1, iterations: 1, maxDuration: '2m' } }, thresholds: { checks: ['rate==1'] } };

export default function () {
  const agents = [
    ['browser', 'Mozilla/5.0 ReqSentryFixture/1.0'],
    ['curl', 'curl/8.0.0'],
    ['python', 'python-requests/2.32.0'],
    ['bot', 'ReqSentryFixtureBot/1.0'],
    ['missing', ''],
    ['rotated', 'ReqSentryRotatingAgent/2.0'],
  ];
  allSites((site) => {
    for (const [kind, agent] of agents) {
      request(site, '/about.html', 'user-agents', kind, { headers: { 'User-Agent': agent }, expected: [200] });
    }
  });
}
