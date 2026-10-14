import forge from "node-forge";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** In-process MITM CA (velric traffic MITM parity): one root CA per
 *  outputRoot (persisted as mitm-ca.cert.pem for client trust), per-host
 *  leaf certs signed on the fly with SAN=host. Pure JS via node-forge —
 *  no native compilation. The CA cert is what a client must trust for the
 *  recorder to decrypt HTTPS. */

export interface MitmCA {
  readonly caCertPem: string;
  /** Sign a leaf certificate for one host (SAN=host, 1y). */
  sign: (host: string) => { keyPem: string; certPem: string };
}

export const createOrLoadCA = async (root: string, commonName = "velric-recorder CA"): Promise<MitmCA> => {
  const keyPath = join(root, "mitm-ca.key.pem");
  const certPath = join(root, "mitm-ca.cert.pem");
  let caKeyPem: string;
  let caCertPem: string;
  try {
    caKeyPem = await readFile(keyPath, "utf8");
    caCertPem = await readFile(certPath, "utf8");
  } catch {
    await mkdir(root, { recursive: true });
    const caKeys = forge.pki.rsa.generateKeyPair(2048);
    const caCert = forge.pki.createCertificate();
    caCert.publicKey = caKeys.publicKey;
    caCert.serialNumber = "01";
    caCert.validity.notBefore = new Date();
    caCert.validity.notAfter = new Date(Date.now() + 10 * 365 * 86400000);
    const attrs = [{ name: "commonName", value: commonName }];
    caCert.setSubject(attrs);
    caCert.setIssuer(attrs);
    caCert.setExtensions([
      { name: "basicConstraints", cA: true, critical: true },
      { name: "keyUsage", keyCertSign: true, critical: true },
    ]);
    caCert.sign(caKeys.privateKey, forge.md.sha256.create());
    caKeyPem = forge.pki.privateKeyToPem(caKeys.privateKey);
    caCertPem = forge.pki.certificateToPem(caCert);
    await writeFile(keyPath, caKeyPem);
    await writeFile(certPath, caCertPem);
  }
  const caKey = forge.pki.privateKeyFromPem(caKeyPem);
  const leafCache = new Map<string, { keyPem: string; certPem: string }>();
  const sign = (host: string): { keyPem: string; certPem: string } => {
    const hit = leafCache.get(host);
    if (hit) return hit;
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = String(Date.now()) + String(host.length);
    cert.validity.notBefore = new Date(Date.now() - 3600000); // tolerate clock skew
    cert.validity.notAfter = new Date(Date.now() + 365 * 86400000);
    cert.setSubject([{ name: "commonName", value: host }]);
    cert.setIssuer(forge.pki.certificateFromPem(caCertPem).subject.attributes);
    // IP hosts need an IPAddress SAN entry (type 7); DNS names use type 2.
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
    cert.setExtensions([{
      name: "subjectAltName",
      altNames: [isIp ? { type: 7, ip: host } : { type: 2, value: host }],
    }]);
    cert.sign(caKey, forge.md.sha256.create());
    const out = { keyPem: forge.pki.privateKeyToPem(keys.privateKey), certPem: forge.pki.certificateToPem(cert) };
    leafCache.set(host, out);
    return out;
  };
  return { caCertPem, sign };
};
