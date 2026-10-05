// Scope every connector fetch, including pagination links and redirects.
const original = globalThis.fetch.bind(globalThis);
const origin = process.env.MITHRIL_ALLOWED_CLOUD_ORIGIN;
if (origin) globalThis.fetch = (input, init) => {
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  if (url.origin !== origin) return Promise.reject(new Error('cloud origin refused'));
  return original(input, { ...init, redirect: 'error' });
};
