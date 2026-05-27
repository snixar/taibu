/**
 * TaiBu MCP — 极简公开端点（无鉴权）
 *
 * 部署到 EdgeOne Pages cloud-functions/fmcp/[[default]].js
 * 零环境变量，零配置。部署后端点：https://<域名>/fmcp
 *
 * 前置：pnpm -C packages/core build
 */

import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  executeTool,
  buildListToolsPayload,
  buildToolSuccessPayload,
  normalizeTransportDetailLevel,
} from 'taibu-core/mcp';

const VERSION = '0.1.0';

function createMcpServer() {
  const server = new McpServer(
    { name: 'taibu-mcp', version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.server.setRequestHandler(ListToolsRequestSchema, () =>
    buildListToolsPayload(),
  );

  server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const toolArgs = args === undefined ? {} : args;
    try {
      const result = await executeTool(name, toolArgs);
      const detailLevel = normalizeTransportDetailLevel(args?.detailLevel);
      return buildToolSuccessPayload(name, result, { detailLevel });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text', text: message }], isError: true };
    }
  });

  return server;
}

async function handleRequest(req, res, parsedBody) {
  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  transport.onclose = () => { server.close().catch(() => {}); };
  transport.onerror = () => { server.close().catch(() => {}); };

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } finally {
    if (req.method === 'GET') {
      res.on('close', () => { server.close().catch(() => {}); });
    } else {
      res.on('finish', () => { server.close().catch(() => {}); });
    }
  }
}

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/', (req, res) => handleRequest(req, res, req.body));
app.get('/', (req, res) => handleRequest(req, res));
app.delete('/', (_req, res) => res.status(204).end());

export default app;
