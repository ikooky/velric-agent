/** Document-start observation with explicitly opt-in gate modifications. */
export interface HookConfig {
  readonly mode?: "passive" | "gate-defeat";
  readonly loginPathRe: string;
  readonly mockTier: string;
  readonly forward: boolean;
  readonly neutralize: { readonly fields: string[]; readonly success: number | string; readonly flags?: Record<string, unknown> };
  readonly stubs: { match: string; body: unknown }[];
  readonly apiPattern: string;
  readonly recordDetail: boolean;
  readonly respMax: number;
  readonly extractUrlsFromResponse: boolean;
  readonly neutralizeVueRouter: boolean;
  readonly recordSse: boolean;
  readonly observe: { readonly storageReads: boolean; readonly cookieReads: boolean; readonly xhrHeaders: boolean };
}

export const DEFAULT_HOOK_CONFIG: HookConfig = {
  mode: "passive",
  loginPathRe: "/(login|signin)(/|$|[?])",
  mockTier: "L1+L2",
  forward: true,
  neutralize: { fields: ["response_code", "code", "errno", "ret", "status"], success: 0, flags: { success: true, message: "ok" } },
  stubs: [],
  apiPattern: "/(api|apis|v[0-9]+|dev|internal|graphql)/|[.]json($|[?])",
  recordDetail: true,
  respMax: 600,
  extractUrlsFromResponse: true,
  neutralizeVueRouter: true,
  recordSse: true,
  observe: { storageReads: false, cookieReads: false, xhrHeaders: true },
};

// String.raw keeps emitted regular expressions independent of TS string escaping.
const PRELOAD_BODY = String.raw`(function () {
  'use strict';
  if (window.__API_RECON_PRELOAD__) return;
  const C = window.__VELRIC_RECON_CONFIG__;
  const gate = C.mode === 'gate-defeat';
  const login = new RegExp(C.loginPathRe, 'i');
  const api = new RegExp(C.apiPattern, 'i');
  const tier = C.mockTier || '';
  const stubs = C.stubs.map(s => ({ re: new RegExp(s.match), body: s.body }));
  const documentId = (globalThis.crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()) + ':' + Math.random();
  let sequence = 0;
  window.__API_RECON_PRELOAD__ = true;
  window.__API_RECON_MODE__ = gate ? 'gate-defeat' : 'passive';
  window.__API_RECON_LOG__ = new Set();
  window.__API_RECON_DETAIL__ = [];
  window.__API_RECON_ROUTES__ = new Set();
  window.__API_RECON_OBSERVE__ = { storage: [], headers: [] };
  const observed = window.__API_RECON_OBSERVE__;
  const limit = Math.max(0, C.respMax || 600);
  function sample(text) { return String(text == null ? '' : text).slice(0, limit); }
  function absolute(value) { try { return new URL(String(value), location.href).href; } catch (_) { return String(value); } }
  function headers(value) { try { return Object.fromEntries(new Headers(value).entries()); } catch (_) { return {}; } }
  function record(entry) {
    entry.documentId = documentId;
    entry.requestId = ++sequence;
    entry.mode = gate ? 'gate-defeat' : 'passive';
    entry.synthetic = entry.source === 'mock';
    window.__API_RECON_LOG__.add(entry.method + ' ' + entry.url);
    if (C.recordDetail) {
      window.__API_RECON_DETAIL__.push(entry);
      if (window.__API_RECON_DETAIL__.length > 4000) window.__API_RECON_DETAIL__.splice(0, 2000);
    }
    return entry;
  }
  function mockFor(url) {
    if (!gate) return undefined;
    if (tier.includes('L1')) for (const s of stubs) { s.re.lastIndex = 0; if (s.re.test(url)) return s.body; }
    if (tier.includes('L3') && api.test(url)) return { response_code: 0, data: {}, success: true };
  }
  function patch(text) {
    if (!gate || !tier.includes('L2') || text.length > 131072) return text;
    try {
      const j = JSON.parse(text);
      if (!j || typeof j !== 'object' || Array.isArray(j)) return text;
      if (!/未登录|未授权|not\s*login|unauthorized|forbidden/i.test(String(j.message || j.msg || ''))) return text;
      for (const key of C.neutralize.fields) if (key in j) j[key] = C.neutralize.success;
      Object.assign(j, C.neutralize.flags || {});
      if (j.data == null) j.data = {};
      return JSON.stringify(j);
    } catch (_) { return text; }
  }
  // Observe at most a bounded prefix. Cancelling the clone is deliberately not
  // awaited: a tee cancellation can wait for the application's branch to close.
  async function readSample(response) {
    const reader = response.body && response.body.getReader();
    if (!reader) return '';
    let out = '', bytes = 0;
    const decoder = new TextDecoder();
    try {
      while (bytes < limit) {
        const chunk = await reader.read();
        if (chunk.done) break;
        const prefix = chunk.value.subarray(0, limit - bytes);
        bytes += prefix.byteLength;
        out += decoder.decode(prefix, { stream: true });
        if (bytes >= limit) break;
      }
      out += decoder.decode();
      return out;
    } finally { reader.cancel().catch(() => {}); }
  }
  const rawFetch = window.fetch;
  window.fetch = function (input, init) {
    let request;
    try { request = new Request(input, init); } catch (_) {}
    const url = request ? request.url : absolute(input && input.url || input);
    const entry = record({ method: request ? request.method : String(init && init.method || input && input.method || 'GET').toUpperCase(), url,
      reqHeaders: request ? headers(request.headers) : headers(init && init.headers), reqBody: null, status: 0, responseBody: null, source: 'fetch' });
    if (request && request.body) request.clone().text().then(text => { entry.reqBody = text; }).catch(err => { entry.requestReadError = String(err); });
    const mock = mockFor(url);
    if (mock !== undefined && C.forward === false) {
      const text = JSON.stringify(mock);
      Object.assign(entry, { status: 200, source: 'mock', synthetic: true, responseBody: sample(text), deliveredResponseBody: sample(text) });
      return Promise.resolve(new Response(text, { status: 200, headers: { 'content-type': 'application/json' } }));
    }
    // Send this same normalized request: serializing FormData twice would use
    // different multipart boundaries in the observation and on the wire.
    const promise = request ? rawFetch.call(this, request) : rawFetch.apply(this, arguments);
    if (gate) return promise.then(async response => {
      entry.status = response.status;
      entry.responseUrl = response.url;
      if (!/json/i.test(response.headers.get('content-type') || '')) return response;
      let text;
      try { text = await response.clone().text(); } catch (err) { entry.responseReadError = String(err); return response; }
      entry.responseBody = sample(text);
      const delivered = patch(text);
      entry.modified = delivered !== text;
      entry.deliveredResponseBody = sample(delivered);
      if (!entry.modified || [204, 205, 304].includes(response.status)) return response;
      return new Response(delivered, { status: response.status, statusText: response.statusText, headers: response.headers });
    });
    // Return the native promise immediately. Body sampling never delays fetch()
    // resolution or the application's access to a streaming response.
    promise.then(response => {
      entry.status = response.status;
      entry.responseUrl = response.url;
      entry.responseHeaders = headers(response.headers);
      if (/json|text\//i.test(response.headers.get('content-type') || '')) {
        try { readSample(response.clone()).then(text => { entry.responseBody = text; }).catch(err => { entry.responseReadError = String(err); }); }
        catch (err) { entry.responseReadError = String(err); }
      }
    }, err => { entry.error = String(err); });
    return promise;
  };

  const rawOpen = XMLHttpRequest.prototype.open;
  const rawSend = XMLHttpRequest.prototype.send;
  const rawHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (method, url) {
    const result = rawOpen.apply(this, arguments);
    this.__recon = { method: String(method).toUpperCase(), url: absolute(url), reqHeaders: {} };
    return result;
  };
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    const result = rawHeader.apply(this, arguments);
    if (this.__recon) {
      const key = String(name).toLowerCase(), h = this.__recon.reqHeaders;
      h[key] = h[key] ? h[key] + ', ' + value : String(value);
      if (C.observe.xhrHeaders && observed.headers.length < 2000) observed.headers.push({ name: key, url: this.__recon.url });
    }
    return result;
  };
  XMLHttpRequest.prototype.send = function (body) {
    const xhr = this, meta = xhr.__recon || { method: 'GET', url: '', reqHeaders: {} };
    const entry = record(Object.assign({}, meta, { reqBody: typeof body === 'string' ? body : body == null ? null : String(body), status: 0, responseBody: null, source: 'xhr' }));
    const mock = mockFor(meta.url);
    if (mock !== undefined && C.forward === false) {
      const text = JSON.stringify(mock);
      Object.assign(entry, { status: 200, source: 'mock', synthetic: true, responseBody: sample(text) });
      setTimeout(() => {
        Object.defineProperties(xhr, { readyState: { configurable: true, value: 4 }, status: { configurable: true, value: 200 },
          responseText: { configurable: true, value: text }, response: { configurable: true, value: xhr.responseType === 'json' ? mock : text } });
        xhr.dispatchEvent(new Event('readystatechange')); xhr.dispatchEvent(new Event('load')); xhr.dispatchEvent(new Event('loadend'));
      }, 0);
      return;
    }
    const listener = function () {
      if (xhr.readyState !== 4) return;
      xhr.removeEventListener('readystatechange', listener);
      // No application callback is replaced. A failed observation is contained
      // inside this listener for every responseType, including throwing getters.
      try {
        entry.status = xhr.status;
        entry.responseUrl = xhr.responseURL;
        const type = xhr.responseType;
        let text = null;
        if (!type || type === 'text') text = xhr.responseText;
        else if (type === 'json') text = JSON.stringify(xhr.response);
        else if (type === 'document') text = xhr.response ? new XMLSerializer().serializeToString(xhr.response) : null;
        else if (type === 'arraybuffer') { entry.responseBytes = xhr.response ? xhr.response.byteLength : 0; }
        else if (type === 'blob' && xhr.response) { entry.responseBytes = xhr.response.size; }
        entry.responseType = type;
        entry.responseBody = text == null ? null : sample(text);
        if (gate && text != null && (!type || type === 'text' || type === 'json')) {
          const delivered = patch(text);
          entry.modified = delivered !== text;
          entry.deliveredResponseBody = sample(delivered);
          if (entry.modified) {
            if (!type || type === 'text') Object.defineProperty(xhr, 'responseText', { configurable: true, value: delivered });
            Object.defineProperty(xhr, 'response', { configurable: true, value: type === 'json' ? JSON.parse(delivered) : delivered });
          }
        }
      } catch (err) { entry.responseReadError = String(err); }
    };
    xhr.addEventListener('readystatechange', listener);
    return rawSend.apply(this, arguments);
  };

  const RawEventSource = window.EventSource;
  if (RawEventSource) {
    window.EventSource = function (url, cfg) {
      window.__API_RECON_LOG__.add('SSE ' + absolute(url));
      if (!gate || C.recordSse === false) return new RawEventSource(url, cfg);
      const stub = new RawEventSource('data:text/event-stream,'); stub.close(); return stub;
    };
    Object.setPrototypeOf(window.EventSource, RawEventSource);
    window.EventSource.prototype = RawEventSource.prototype;
  }
  if (C.observe.storageReads) {
    const rawGet = Storage.prototype.getItem;
    Storage.prototype.getItem = function (key) { if (observed.storage.length < 1000) observed.storage.push({ type: 'getItem', key, at: location.pathname }); return rawGet.apply(this, arguments); };
  }
  if (C.observe.cookieReads) {
    const d = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (d && d.get) Object.defineProperty(document, 'cookie', { configurable: true, get() { if (observed.storage.length < 1000) observed.storage.push({ type: 'cookieRead', at: location.pathname }); return d.get.call(this); }, set: d.set });
  }
  const blocked = url => gate && login.test(String(url || ''));
  if (gate) {
    for (const name of ['pushState', 'replaceState']) {
      const raw = history[name]; history[name] = function (state, title, url) { if (blocked(url)) return; return raw.apply(this, arguments); };
    }
    for (const name of ['assign', 'replace']) {
      try { const raw = Location.prototype[name]; Location.prototype[name] = function (url) { if (blocked(url)) return; return raw.apply(this, arguments); }; } catch (_) {}
    }
  }
  function routers() {
    try {
      const el = document.querySelector('[data-v-app]') || document.querySelector('#app');
      const app = el && el.__vue_app__ || window.__VUE__, vm = el && el.__vue__;
      const router = vm ? vm.$router || vm.$root && vm.$root.$router : app && app.config && app.config.globalProperties.$router;
      if (router && router.getRoutes) for (const r of router.getRoutes()) if (r.path) window.__API_RECON_ROUTES__.add(r.path);
      if (router && gate && C.neutralizeVueRouter && !router.__apiReconWrapped) {
        for (const name of ['push', 'replace']) if (router[name]) { const raw = router[name]; router[name] = function (loc) { if (blocked(typeof loc === 'string' ? loc : loc && (loc.path || loc.fullPath))) return Promise.resolve(); return raw.apply(this, arguments); }; }
        router.__apiReconWrapped = true;
      }
      if (gate) for (const name of ['goPage', 'navigateTo', 'jumpTo', 'redirectTo']) {
        if (typeof window[name] !== 'function' || window[name].__apiReconWrapped) continue;
        const raw = window[name]; window[name] = function (arg) { if (blocked(typeof arg === 'string' ? arg : arg && arg.path)) return; return raw.apply(this, arguments); }; window[name].__apiReconWrapped = true;
      }
    } catch (_) {}
  }
  document.addEventListener('DOMContentLoaded', routers);
  window.addEventListener('load', routers);
})();`;

const safeJsonForScript = (value: unknown): string => JSON.stringify(value)
  .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029").replace(/<\/script/gi, "<\\/script");

export const buildPreloadScript = (config: HookConfig): string =>
  `window.__VELRIC_RECON_CONFIG__ = ${safeJsonForScript({ ...DEFAULT_HOOK_CONFIG, ...config, observe: { ...DEFAULT_HOOK_CONFIG.observe, ...config.observe } })};\n${PRELOAD_BODY}`;
