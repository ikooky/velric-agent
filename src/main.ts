import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { PRODUCT_IDENTITY } from "./identity.js";
import { registerAllTools } from "./server/registerTools.js";

/**
 * Start the stateless stdio MCP server exposing the recon toolset. The server
 * holds no state between tool calls: every tool reads its arguments, does its
 * work, writes artifacts under a caller-supplied output_root, and returns.
 */
export const runMcp = async (): Promise<number> => {
  const server = new McpServer(
    {
      name: PRODUCT_IDENTITY.serverName,
      title: PRODUCT_IDENTITY.displayName,
      version: PRODUCT_IDENTITY.packageVersion,
    },
    { capabilities: { tools: {} } },
  );
  registerAllTools(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  return 0;
};