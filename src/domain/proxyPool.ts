import { readFile } from "node:fs/promises";
let globalPool: ProxyPool | undefined;
export const setProxyPool = (pool?: ProxyPool): void => { globalPool = pool; };
export const getProxyPool = (): ProxyPool | undefined => globalPool;

/** Proxy pool: round-robin rotation with failure tracking and ejection.
 *  Supports http(s):// and socks5:// URIs (socks via undici socks-dispatcher
 *  when available; otherwise reported as unsupported at fetch time). */

export interface ProxyPoolOptions {
  /** File with one proxy URI per line (# comments allowed) or array. */
  readonly proxiesFile?: string;
  readonly proxies?: string[];
  /** Eject a proxy after N consecutive failures (default 3). */
  readonly failThreshold?: number;
}

interface ProxyState {
  readonly uri: string;
  fails: number;
  uses: number;
}

export class ProxyPool {
  private readonly states: ProxyState[] = [];
  private cursor = 0;
  private readonly failThreshold: number;

  constructor(options: ProxyPoolOptions) {
    this.failThreshold = options.failThreshold ?? 3;
    const list = options.proxies ?? [];
    for (const uri of list) this.states.push({ uri, fails: 0, uses: 0 });
  }

  static async fromFile(file: string, failThreshold?: number): Promise<ProxyPool> {
    const text = await readFile(file, "utf8");
    const proxies = text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    return new ProxyPool({ proxies, failThreshold });
  }

  get size(): number {
    return this.states.length;
  }

  get alive(): number {
    return this.states.filter((s) => s.fails < this.failThreshold).length;
  }

  /** Next healthy proxy (round-robin); null when the pool is exhausted. */
  next(): string | null {
    const healthy = this.states.filter((s) => s.fails < this.failThreshold);
    if (healthy.length === 0) return null;
    // rotate over healthy entries only
    for (let i = 0; i < this.states.length; i++) {
      const s = this.states[this.cursor % this.states.length]!;
      this.cursor++;
      if (s.fails < this.failThreshold) {
        s.uses++;
        return s.uri;
      }
    }
    return null;
  }

  reportSuccess(uri: string): void {
    const s = this.states.find((x) => x.uri === uri);
    if (s) s.fails = 0;
  }

  reportFailure(uri: string): void {
    const s = this.states.find((x) => x.uri === uri);
    if (s) s.fails++;
  }

  snapshot(): { uri: string; fails: number; uses: number; ejected: boolean }[] {
    return this.states.map((s) => ({ uri: s.uri, fails: s.fails, uses: s.uses, ejected: s.fails >= this.failThreshold }));
  }
}
