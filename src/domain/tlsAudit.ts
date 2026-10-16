import type { SecureVersion, TLSSocket, PeerCertificate } from "node:tls";
import { createHash } from "node:crypto";
import { openTunnel, type TunnelOptions } from "../adapters/rawTunnel.js";
import { executionRunId, recordReceipt } from "../core/execution.js";
export interface TlsAudit {
  readonly negotiated: { protocol: string; cipher: string } | null;
  readonly cert: { subject: string; issuer: string; validFrom: string; validTo: string; daysRemaining: number; expired: boolean } | null;
  readonly weakProtocols: string[];
  readonly protocolProbes?: { version: string; outcome: "accepted" | "not-accepted" | "client-unsupported" | "inconclusive"; error?: string }[];
  readonly certificatePolicy?: "verify" | "insecure";
  readonly certificateAuthorized?: boolean; readonly certificateError?: string;
  readonly error?: string;
}
export type TlsAuditOptions = Pick<TunnelOptions, "proxy" | "timeoutMs" | "signal" | "rejectUnauthorized" | "proxyRejectUnauthorized">;
const hash = (v: unknown): string => createHash("sha256").update(JSON.stringify(v)).digest("hex");
export const tlsCertificate = async (url: URL, options: TlsAuditOptions = {}): Promise<PeerCertificate> => {
  const socket = await openTunnel({ host: url.hostname.replace(/^\[|\]$/g, ""), port: Number(url.port) || 443, secure: true, ...options }) as TLSSocket;
  try { return socket.getPeerCertificate(); } finally { socket.destroy(); }
};
export const connectTlsAudit = async (url: URL, options: TlsAuditOptions = {}): Promise<TlsAudit> => {
  const host = url.hostname.replace(/^\[|\]$/g, ""); const port = Number(url.port) || 443;
  const certificatePolicy = options.rejectUnauthorized ? "verify" : "insecure";
  const probe = async (version?: SecureVersion): Promise<{ protocol: string; cipher: string; certificate: PeerCertificate; authorized: boolean; authorizationError: string }> => {
    const socket = await openTunnel({ host, port, secure: true, ...options, ...(version ? { minVersion: version, maxVersion: version } : {}) }) as TLSSocket;
    try {
      const result = { protocol: socket.getProtocol() ?? "", cipher: socket.getCipher()?.name ?? "", certificate: socket.getPeerCertificate(), authorized: socket.authorized, authorizationError: String(socket.authorizationError ?? "") };
      if (executionRunId() !== "unbound") await recordReceipt({ url: url.href, method: "TLS", status: null, requestHash: hash({ host, port, version: version ?? "default", certificatePolicy }), responseHash: hash(result), complete: true });
      return result;
    } finally { socket.destroy(); }
  };
  let baseline: Awaited<ReturnType<typeof probe>>;
  try { baseline = await probe(); } catch (e) { return { negotiated: null, cert: null, weakProtocols: [], certificatePolicy, protocolProbes: [], error: e instanceof Error ? e.message : String(e) }; }
  const certificate = baseline.certificate; let cert: TlsAudit["cert"] = null;
  if (certificate?.valid_to) {
    const expires = new Date(certificate.valid_to).getTime();
    cert = { subject: JSON.stringify(certificate.subject ?? {}), issuer: JSON.stringify(certificate.issuer ?? {}), validFrom: certificate.valid_from ?? "", validTo: certificate.valid_to, daysRemaining: Math.floor((expires - Date.now()) / 86400000), expired: expires < Date.now() };
  }
  const weakProtocols: string[] = []; const protocolProbes: NonNullable<TlsAudit["protocolProbes"]> = [];
  for (const version of ["TLSv1", "TLSv1.1"] as SecureVersion[]) {
    try {
      const r = await probe(version);
      const accepted = r.protocol === version;
      protocolProbes.push({ version, outcome: accepted ? "accepted" : "inconclusive" });
      if (accepted) weakProtocols.push(`${version} accepted`);
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      const clientUnsupported = /no protocols available|no ciphers available|unsupported protocol|not supported|ERR_TLS_INVALID_PROTOCOL/i.test(error);
      // Handshake failure can be client policy, interception, or remote rejection. Never call it proof of refusal.
      protocolProbes.push({ version, outcome: clientUnsupported ? "client-unsupported" : "inconclusive", error });
    }
  }
  return { negotiated: { protocol: baseline.protocol, cipher: baseline.cipher }, cert, weakProtocols, protocolProbes, certificatePolicy, certificateAuthorized: baseline.authorized, ...(baseline.authorizationError ? { certificateError: baseline.authorizationError } : {}) };
};
