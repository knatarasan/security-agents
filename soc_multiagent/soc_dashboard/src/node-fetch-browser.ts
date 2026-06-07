// Browser stub for node-fetch — replaces the Node.js-only package
// so Vite can bundle CopilotKit without crashing on stream/http imports.
const _fetch: typeof fetch = (input, init) => globalThis.fetch(input as RequestInfo, init);
export default _fetch;
export const Headers = globalThis.Headers;
export const Request = globalThis.Request;
export const Response = globalThis.Response;
export const FetchError = class FetchError extends Error {};
export const AbortError = class AbortError extends Error {};
export const isRedirect = (_code: number) => false;
