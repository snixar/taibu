/**
 * TaiBu MCP Server — Docker / 长驻进程入口
 */

import { config } from 'dotenv';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const currentFileDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(currentFileDir, '../../..');
config({ path: resolve(repoRoot, '.env'), override: false });

import { createApp } from './app.js';

const app = createApp({ statelessOnly: false });

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.MCP_HOST || '127.0.0.1';

const httpServer = app.listen(PORT, HOST, () => {
  console.log(
    `TaiBu MCP Server (Streamable HTTP + OAuth 2.1) running on ${HOST}:${PORT} at /mcp`,
  );
});

function gracefulShutdown(signal: string) {
  console.log(`\n[${signal}] Shutting down MCP server...`);

  httpServer.close(() => {
    console.log('HTTP server closed');
  });

  setTimeout(() => {
    process.exit(0);
  }, 3000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
