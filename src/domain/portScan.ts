import { connect } from "node:net";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

/** TCP connect port scan (top-ports list, no SYN). Deterministic, bounded. */

export interface PortScanInput {
  readonly host: string;
  readonly outputRoot: string;
  readonly ports?: number[];
  readonly timeoutMs?: number;
  readonly concurrency?: number;
}

export interface PortScanResult {
  readonly host: string;
  readonly scanned: number;
  readonly open: { port: number; service: string }[];
  readonly artifacts: { path: string; bytes: number }[];
}

/** Top ports worth touching in recon; keyed service names are best-effort. */
export const TOP_PORTS: ReadonlyArray<readonly [number, string]> = [
  [21, "ftp"], [22, "ssh"], [23, "telnet"], [25, "smtp"], [53, "dns"],
  [80, "http"], [110, "pop3"], [135, "msrpc"], [139, "netbios"], [143, "imap"],
  [443, "https"], [445, "smb"], [465, "smtps"], [587, "submission"], [993, "imaps"],
  [995, "pop3s"], [1080, "socks"], [1433, "mssql"], [1521, "oracle"], [2049, "nfs"],
  [2181, "zookeeper"], [2375, "docker"], [2376, "docker-tls"], [3000, "node-dev"],
  [3306, "mysql"], [3389, "rdp"], [4443, "https-alt"], [4848, "glassfish"],
  [5000, "upnp/flask"], [5432, "postgres"], [5601, "kibana"], [5900, "vnc"],
  [5984, "couchdb"], [6379, "redis"], [6443, "k8s-api"], [7001, "weblogic"],
  [7002, "weblogic-tls"], [7070, "http-alt"], [8000, "http-alt"], [8008, "http-alt"],
  [8009, "ajp"], [8010, "http-alt"], [8069, "liferay"], [8080, "http-proxy"],
  [8081, "http-alt"], [8088, "http-alt"], [8090, "http-alt"], [8161, "activemq"],
  [8443, "https-alt"], [8500, "consul"], [8888, "http-alt"], [8983, "solr"],
  [9000, "sonarqube"], [9001, "supervisor"], [9090, "prometheus"], [9092, "kafka-console"],
  [9200, "elasticsearch"], [9300, "es-transport"], [9443, "https-alt"],
  [10000, "webmin"], [10250, "kubelet"], [11211, "memcached"], [15672, "rabbitmq-mgmt"],
  [27017, "mongodb"], [28017, "mongodb-web"], [50000, "sap"], [55555, "meshcentral"],
];

const scanOne = async (host: string, port: number, timeoutMs: number): Promise<boolean> =>
  new Promise((resolveOpen) => {
    const sock = connect({ host, port });
    const done = (v: boolean): void => {
      sock.removeAllListeners();
      sock.destroy();
      resolveOpen(v);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });

export const scanPorts = async (input: PortScanInput): Promise<PortScanResult> => {
  const ports = input.ports ?? TOP_PORTS.map(([p]) => p);
  const timeoutMs = input.timeoutMs ?? 2500;
  const concurrency = input.concurrency ?? 64;
  await mkdir(input.outputRoot, { recursive: true });

  const open: { port: number; service: string }[] = [];
  const serviceByPort = new Map(TOP_PORTS);
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < ports.length) {
      const p = ports[cursor++];
      if (p === undefined) continue;
      if (await scanOne(input.host, p, timeoutMs)) {
        open.push({ port: p, service: serviceByPort.get(p) ?? "?" });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  open.sort((a, b) => a.port - b.port);

  const path = join(input.outputRoot, "ports_open.txt");
  const body = open.map((o) => `${o.port}\t${o.service}`).join("\n");
  await writeFile(path, body);
  return { host: input.host, scanned: ports.length, open, artifacts: [{ path, bytes: Buffer.byteLength(body) }] };
};
