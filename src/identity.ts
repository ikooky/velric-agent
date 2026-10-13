import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

interface PackageJson {
  name: string;
  version: string;
  mcpName?: string;
}

const pkg = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
) as PackageJson;

/** Canonical public identity shared by packaging, setup, MCP, and skill install. */
export const PRODUCT_IDENTITY = {
  displayName: "velric-agent",
  packageName: pkg.name,
  packageVersion: pkg.version,
  packageSpecifier: `${pkg.name}@latest`,
  registrationPackageSpecifier: `${pkg.name}@${pkg.version}`,
  cliBinary: "velric-agent",
  mcpServerKey: "velric-agent",
  mcpCommand: `npx -y ${pkg.name}@${pkg.version} mcp`,
  skillName: "velric-recon",
  serverName: pkg.mcpName ?? `io.github.ikooky/${pkg.name}`,
} as const;

/** Resolve the package root (one level up from dist/ or src/). */
export const packageRootDir = (): string => packageRoot;