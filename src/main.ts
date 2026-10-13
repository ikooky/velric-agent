import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import { PRODUCT_IDENTITY } from "./identity.js";
import { registerAllTools } from "./server/registerTools.js";
import { SERVER_INSTRUCTIONS } from "./server/workflow.js";


/**
 * MCP resources + prompts: expose the driver playbook and workflow guide as
 * first-class MCP surfaces (hosts discover them without calling tools), and
 * let hosts read any hunt's graph.json live as a resource.
 */
const registerResourcesAndPrompts = async (server: McpServer): Promise<void> => {
  const { DRIVER_PLAYBOOK } = await import("./application/huntDriver.js");
  const { WORKFLOW_GUIDE } = await import("./server/workflow.js");

  server.registerResource(
    "driver-playbook",
    "velric://driver-playbook",
    { description: "Host-driven hunt playbook: planner/worker disciplines, evidence gates, red lines." },
    async () => ({
      contents: [{ uri: "velric://driver-playbook", mimeType: "text/markdown", text: DRIVER_PLAYBOOK }],
    }),
  );

  server.registerResource(
    "workflow-guide",
    "velric://workflow-guide",
    { description: "Phase 0-5 recon workflow guide with per-tool usage." },
    async () => ({
      contents: [{ uri: "velric://workflow-guide", mimeType: "text/markdown", text: WORKFLOW_GUIDE as unknown as string }],
    }),
  );

  server.registerPrompt(
    "hunt-driver",
    { title: "Start a host-driven hunt", description: "Boots the full planner+worker driver instructions for a new hunt.", argsSchema: { goal: z.string(), outputRoot: z.string() } },
    async ({ goal, outputRoot }: { goal: string; outputRoot: string }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `You are the planner+worker brain for a velric-agent hunt. Goal: ${goal}\nWorkspace: ${outputRoot}\n\n${DRIVER_PLAYBOOK}\n\nStart now: call hunt_begin, then loop hunt_overview → recon tools (observationLedgerRoot=${outputRoot}) → hunt_record.`,
          },
        },
      ],
    }),
  );
};
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
    {
      capabilities: { tools: {} },
      instructions: SERVER_INSTRUCTIONS,
    },
  );
  registerAllTools(server);
  await registerResourcesAndPrompts(server);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  return 0;
};