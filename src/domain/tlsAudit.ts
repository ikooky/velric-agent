import { connect as tlsConnect } from "node:tls";
import type { SecureVersion } from "node:tls";

/** TLS configuration audit (sslscan-lite, node:tls based): negotiated
 *  protocol + cipher, certificate validity/expiry, and weak-protocol probes
 *  (SSLv3/TLS1.0/1.1 should be refused). No external binary. */

export interface TlsAudit {
  readonly negotiated: { protocol: string; cipher: string } | null;
  readonly cert: {
    readonly subject: string;
    readonly issuer: string;
    readonly validFrom: string;
    readonly validTo: string;
    readonly daysRemaining: number;
    readonly expired: boolean;
  } | null;
  /** legacy protocols the endpoint STILL accepts (findings, not info). */
  readonly weakProtocols: string[];
  readonly error?: string;
}

const probe = (host: string, port: number, secureOptions?: { minVersion?: SecureVersion; maxVersion?: SecureVersion }): Promise<{ protocol: string; cipher: string } | null> =>
  new Promise((resolve) => {
    let settled = false;
    const done = (v: { protocol: string; cipher: string } | null): void => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* gone */ }
      resolve(v);
    };
    const sock = tlsConnect({
      host, port,
      rejectUnauthorized: false, // recon targets: self-signed is signal, not error
      servername: host,
      ALPNProtocols: ["http/1.1"],
      ...(secureOptions?.minVersion ? { minVersion: secureOptions.minVersion } : {}),
      ...(secureOptions?.maxVersion ? { maxVersion: secureOptions.maxVersion } : {}),
      timeout: 6000,
    }, () => {
      const p = sock.getProtocol();
      const c = sock.getCipher();
      done(p && c ? { protocol: p, cipher: c.name } : null);
    });
    sock.on("timeout", () => done(null));
    sock.on("error", () => done(null));
  });

export const connectTlsAudit = async (url: URL): Promise<TlsAudit> => {
  const host = url.hostname;
  const port = url.port ? Number(url.port) : 443;

  const negotiated = await probe(host, port);
  if (!negotiated) return { negotiated: null, cert: null, weakProtocols: [], error: "TLS connect failed" };

  // certificate details off the live socket
  const certInfo = await new Promise<TlsAudit["cert"]>((resolve) => {
    let settled = false;
    const done = (v: TlsAudit["cert"]): void => { if (!settled) { settled = true; try { s.destroy(); } catch { } resolve(v); } };
    const s = tlsConnect({ host, port, rejectUnauthorized: false, servername: host, timeout: 6000 }, () => {
      const cert = s.getPeerCertificate();
      if (!cert || !cert.valid_to) return done(null);
      const to = new Date(cert.valid_to);
      const days = Math.round((to.getTime() - Date.now()) / 86400000);
      done({
        subject: JSON.stringify(cert.subject ?? {}),
        issuer: JSON.stringify(cert.issuer ?? {}),
        validFrom: cert.valid_from ?? "",
        validTo: cert.valid_to,
        daysRemaining: days,
        expired: days < 0,
      });
    });
    s.on("timeout", () => done(null));
    s.on("error", () => done(null));
  });

  // weak protocol probes: explicitly allow the legacy floor
  const weak: string[] = [];
  const weakProbes: ReadonlyArray<readonly [string, { maxVersion?: SecureVersion }]> = [
    ["SSLv3/TLS1.0-or-lower accepted", { maxVersion: "TLSv1" }],
    ["TLS1.1 accepted", { maxVersion: "TLSv1.1" }],
  ];
  for (const [label, opts] of weakProbes) {
    const r = await probe(host, port, opts);
    if (r && (r.protocol === "SSLv3" || r.protocol === "TLSv1" || r.protocol === "TLSv1.1")) weak.push(`${label} (${r.protocol})`);
  }

  return { negotiated, cert: certInfo, weakProtocols: weak };
};
