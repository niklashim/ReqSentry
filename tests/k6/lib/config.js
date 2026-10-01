export const SITE1_URL = (__ENV.SITE1_URL || 'http://reqsentry-web:8081').replace(/\/$/, '');
export const SITE2_URL = (__ENV.SITE2_URL || 'http://reqsentry-web:8082').replace(/\/$/, '');
export const SITE3_URL = (__ENV.SITE3_URL || 'http://reqsentry-web:8083').replace(/\/$/, '');
export const SITE4_URL = (__ENV.SITE4_URL || 'http://reqsentry-web:8084').replace(/\/$/, '');

export const sites = ['him.com', 'mycoolshop.se', 'ekstrom.nu', 'wordpress-site.com'];

export function baseURL(site) {
  if (site === sites[0]) return SITE1_URL;
  if (site === sites[1]) return SITE2_URL;
  if (site === sites[2]) return SITE3_URL;
  if (site === sites[3]) return SITE4_URL;
  throw new Error(`unknown site ${site}`);
}

export function positiveInteger(name, fallback, maximum) {
  const raw = __ENV[name] || String(fallback);
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer from 1 to ${maximum}`);
  }
  return value;
}
