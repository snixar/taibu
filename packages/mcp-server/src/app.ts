/**
 * TaiBu MCP Server — Express 应用工厂
 *
 * 共享 Express app 创建逻辑，供 Docker（index.ts）和 EdgeOne Cloud Functions 共用。
 */

import crypto from 'crypto';
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  isInitializeRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';

import {
  executeTool,
  buildListToolsPayload,
  buildToolSuccessPayload,
  normalizeTransportDetailLevel,
} from 'taibu-core/mcp';
import { createRequire } from 'node:module';

import {
  dualAuthMiddleware,
  rateLimitMiddleware,
  oauthRateLimitMiddleware,
  originValidationMiddleware,
  hostValidationMiddleware,
  sseConnectionLimitMiddleware,
  readPositiveIntEnv,
  type McpAuthInfo,
} from './middleware.js';

import { TaiBuOAuthProvider } from './oauth/provider.js';
import { cleanupOAuthArtifactsTransactionally, saveAuthorizationCode } from './oauth/store.js';
import { renderAuthorizePage } from './oauth/authorize-page.js';
import { validateOAuthLoginRequest } from './oauth/login-validation.js';
import { getAllowedTokenAudiences } from './oauth/jwt.js';
import { isOAuthDebugEnabled, oauthError } from './oauth/logger.js';
import { getSupabaseAuthClient } from './supabase.js';
import {
  attachPlaceResolutionInfoToResult,
  attachPlaceResolutionNoteToPayload,
  decorateToolListPayloadForRuntime,
  preprocessToolArgsForRuntimePlace,
} from './place-resolution.js';

const require = createRequire(import.meta.url);
const { version } = require('../package.json') as { version: string };

// ─── 配置常量 ───
const MAX_TOTAL_SESSIONS = readPositiveIntEnv('MCP_MAX_SESSIONS', 1000);
const SESSION_TTL = readPositiveIntEnv('MCP_SESSION_TTL_MS', 1800000);
const SESSION_IDLE = readPositiveIntEnv('MCP_SESSION_IDLE_MS', 600000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const SEED_SCOPED_TOOLS = new Set(['liuyao', 'tarot']);

type SessionContext = {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
  auth: McpAuthInfo;
  createdAt: number;
  lastActivityAt: number;
};

// ─── 工具执行 ───

function withSeedScope(name: string, args: unknown, auth: McpAuthInfo): unknown {
  if (!SEED_SCOPED_TOOLS.has(name)) {
    return args === undefined ? {} : args;
  }
  if (args === undefined) {
    return { seedScope: auth.userId };
  }
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return args;
  }
  return {
    ...(args as Record<string, unknown>),
    seedScope: auth.userId,
  };
}

// ─── MCP Server 工厂 ───

function createMcpServer(auth: McpAuthInfo) {
  const server = new McpServer(
    { name: 'taibu-mcp-online', version },
    { capabilities: { tools: {} } }
  );

  server.server.setRequestHandler(ListToolsRequestSchema, async () =>
    decorateToolListPayloadForRuntime(buildListToolsPayload()),
  );

  server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const seedScopedArgs = withSeedScope(name, args, auth);
    const { toolArgs, placeResolutionInfo } = await preprocessToolArgsForRuntimePlace(
      name,
      seedScopedArgs,
    );

    try {
      const rawResult = await executeTool(name, toolArgs);
      const result = attachPlaceResolutionInfoToResult(rawResult, placeResolutionInfo);
      const detailLevel = normalizeTransportDetailLevel(args?.detailLevel);
      const payload = buildToolSuccessPayload(name, result, { detailLevel }) as Record<string, unknown>;
      return attachPlaceResolutionNoteToPayload(payload, placeResolutionInfo);
    } catch (error) {
      const internalMessage = error instanceof Error ? error.message : String(error);
      const userMessage = IS_PRODUCTION ? 'Tool execution failed' : `Error: ${internalMessage}`;
      return {
        content: [{ type: 'text', text: userMessage }],
        isError: true,
      };
    }
  });

  return server;
}

// ─── 会话管理（仅非 stateless 模式使用）───

export type AppOptions = {
  /** 强制 stateless 模式 — Cloud Functions 使用，禁用内存会话 */
  statelessOnly?: boolean;
};

export function createApp(options?: AppOptions): express.Express {
  const statelessOnly = options?.statelessOnly ?? false;

  // ─── OAuth Provider ───
  const oauthProvider = new TaiBuOAuthProvider();
  const issuerUrl = new URL(process.env.MCP_ISSUER_URL || 'https://mcp.mingai.fun');
  const scopesSupported = ['mcp:tools'] as const;
  const resourceName = 'TaiBu MCP Server';
  const resourceServerUrl = new URL('/mcp', issuerUrl);

  const oauthMetadataCompatibility = {
    issuer: issuerUrl.href,
    authorization_endpoint: new URL('/authorize', issuerUrl).href,
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint: new URL('/token', issuerUrl).href,
    token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: [...scopesSupported],
    revocation_endpoint: new URL('/revoke', issuerUrl).href,
    revocation_endpoint_auth_methods_supported: ['client_secret_post'],
    registration_endpoint: new URL('/register', issuerUrl).href,
  };

  const protectedResourceMetadataCompatibility = {
    resource: resourceServerUrl.href,
    authorization_servers: [issuerUrl.href],
    scopes_supported: [...scopesSupported],
    resource_name: resourceName,
  };

  const app = express();

  if (process.env.MCP_TRUST_PROXY === 'true') {
    app.set('trust proxy', true);
  }

  // ─── 调试日志 ───
  if (isOAuthDebugEnabled()) {
    app.use((req, _res, next) => {
      const oauthPaths = ['/register', '/token', '/authorize', '/revoke', '/.well-known/'];
      if (oauthPaths.some((p) => req.path.startsWith(p))) {
        console.log(`[OAuth:req] ${req.method} ${req.path}`);
      }
      next();
    });

    app.use((req, res, next) => {
      if (req.path !== '/' && req.path !== '/mcp') return next();
      const accept = req.headers.accept ?? 'none';
      const hasAuth =
        typeof req.headers.authorization === 'string' ||
        typeof req.headers['x-api-key'] === 'string';
      const sessionId =
        typeof req.headers['mcp-session-id'] === 'string'
          ? (req.headers['mcp-session-id'] as string)
          : '';
      const protocolVersion =
        typeof req.headers['mcp-protocol-version'] === 'string'
          ? (req.headers['mcp-protocol-version'] as string)
          : '';
      const sessionMark = sessionId ? ` session=${sessionId.slice(0, 8)}...` : '';
      const protocolMark = protocolVersion ? ` proto=${protocolVersion}` : '';

      res.on('finish', () => {
        console.log(
          `[MCP:req] ${req.method} ${req.path} status=${res.statusCode} accept=${accept} auth=${hasAuth ? 'yes' : 'no'}${sessionMark}${protocolMark}`,
        );
      });
      next();
    });
  }

  // ─── OAuth 限流 ───
  app.use(['/register', '/token', '/revoke'], oauthRateLimitMiddleware);

  // ─── OAuth 路由 ───
  app.use(
    mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl,
      resourceServerUrl,
      scopesSupported: [...scopesSupported],
      resourceName,
      authorizationOptions: { rateLimit: false },
      tokenOptions: { rateLimit: false },
      clientRegistrationOptions: { rateLimit: false },
      revocationOptions: { rateLimit: false },
    }),
  );

  // ─── OAuth 登录表单 ───
  app.post(
    '/oauth/login',
    oauthRateLimitMiddleware,
    express.urlencoded({ extended: false }),
    async (req, res) => {
      const {
        email,
        password,
        client_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        state,
        scope,
        resource,
      } = req.body as Record<string, string>;

      if (!email || !password || !client_id || !redirect_uri || !code_challenge) {
        const html = renderAuthorizePage({
          clientId: client_id || '',
          redirectUri: redirect_uri || '',
          codeChallenge: code_challenge || '',
          codeChallengeMethod: code_challenge_method || 'S256',
          state,
          scope,
          resource,
          scopes: scope ? scope.split(' ') : [],
          error: '请填写邮箱和密码',
        });
        return res.status(400).send(html);
      }

      let client;
      try {
        client = await oauthProvider.clientsStore.getClient(client_id);
      } catch (error) {
        oauthError('OAuth client lookup failed', error);
        return res.status(500).json({ error: 'OAuth service unavailable' });
      }
      if (!client) {
        return res.status(400).json({ error: 'Invalid client_id' });
      }

      const validation = validateOAuthLoginRequest({
        client,
        redirectUri: redirect_uri,
        scope,
        resource,
        issuerUrl,
        allowedAudiences: getAllowedTokenAudiences(issuerUrl),
      });

      if (!validation.ok) {
        const errorMessageMap: Record<string, string> = {
          'Invalid redirect_uri': 'redirect_uri 非法或未注册',
          'Invalid scope': 'scope 非法或超出客户端权限',
          'Invalid resource': 'resource 非法',
        };
        const html = renderAuthorizePage({
          clientName: client.client_name,
          clientId: client_id,
          redirectUri: redirect_uri,
          codeChallenge: code_challenge,
          codeChallengeMethod: code_challenge_method || 'S256',
          state,
          scope,
          resource,
          scopes: scope ? scope.split(' ') : [],
          error: errorMessageMap[validation.error] || '授权参数非法',
        });
        return res.status(400).send(html);
      }

      const validated = validation.value;

      const supabase = getSupabaseAuthClient();
      const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (authError || !authData.user) {
        const html = renderAuthorizePage({
          clientName: client.client_name,
          clientId: client_id,
          redirectUri: validated.redirectUri,
          codeChallenge: code_challenge,
          codeChallengeMethod: code_challenge_method || 'S256',
          state,
          scope: validated.scope,
          resource: validated.resource,
          scopes: validated.scopes,
          error: '邮箱或密码错误',
        });
        return res.status(401).send(html);
      }

      try {
        const code = await saveAuthorizationCode({
          clientId: client_id,
          userId: authData.user.id,
          redirectUri: validated.redirectUri,
          codeChallenge: code_challenge,
          scope: validated.scope,
          resource: validated.resource,
        });

        const redirectUrl = new URL(validated.redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (state) redirectUrl.searchParams.set('state', state);
        res.redirect(302, redirectUrl.href);
      } catch {
        const html = renderAuthorizePage({
          clientName: client.client_name,
          clientId: client_id,
          redirectUri: validated.redirectUri,
          codeChallenge: code_challenge,
          codeChallengeMethod: code_challenge_method || 'S256',
          state,
          scope: validated.scope,
          resource: validated.resource,
          scopes: validated.scopes,
          error: '授权失败，请重试',
        });
        return res.status(500).send(html);
      }
    },
  );

  app.use(express.json({ limit: '1mb' }));

  app.get('/info', (_req, res) => {
    res.status(200).json({
      name: 'TaiBu MCP Server',
      status: 'ok',
      transport: 'streamable-http',
      mcp_endpoint: resourceServerUrl.pathname,
      oauth_authorization_server_metadata: '/.well-known/oauth-authorization-server',
      oauth_protected_resource_metadata: `/.well-known/oauth-protected-resource${resourceServerUrl.pathname}`,
    });
  });

  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.status(200).json(oauthMetadataCompatibility);
  });

  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.status(200).json(protectedResourceMetadataCompatibility);
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  if (!IS_PRODUCTION) {
    app.get('/dev/authorize-preview', (_req, res) => {
      const html = renderAuthorizePage({
        clientName: 'ChatGPT',
        scopes: ['mcp:tools'],
        clientId: 'preview-client-id',
        redirectUri: 'https://example.com/callback',
        codeChallenge: 'preview-challenge',
        codeChallengeMethod: 'S256',
        state: 'preview-state',
        scope: 'mcp:tools',
        error: _req.query.error === '1' ? '邮箱或密码错误' : undefined,
      });
      res.send(html);
    });
  }

  // ─── MCP 认证中间件 ───
  const mcpAuth = dualAuthMiddleware(oauthProvider);

  // ─── Stateless 请求处理 ───
  async function handleStatelessRequest(
    req: express.Request,
    res: express.Response,
    auth: McpAuthInfo,
    parsedBody?: unknown,
  ) {
    const server = createMcpServer(auth);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    transport.onclose = () => {
      void server.close().catch(() => {});
    };
    transport.onerror = () => {
      void server.close().catch(() => {});
    };

    let closed = false;
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, parsedBody);
    } catch (error) {
      closed = true;
      await server.close().catch(() => {});
      if (!res.headersSent) {
        return res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
      throw error;
    } finally {
      if (!closed) {
        if (req.method === 'GET') {
          res.on('close', () => {
            void server.close().catch(() => {});
          });
        } else {
          await server.close().catch(() => {});
        }
      }
    }
  }

  // ─── 会话管理（仅非 stateless 模式）───
  const sessions = new Map<string, SessionContext>();

  function getSessionIdHeader(req: express.Request): string | undefined {
    const sessionId = req.headers['mcp-session-id'];
    return typeof sessionId === 'string' ? sessionId : undefined;
  }

  function cleanupSession(sessionId: string) {
    const session = sessions.get(sessionId);
    if (!session) return;
    sessions.delete(sessionId);
    session.server.close().catch(() => {});
  }

  function isSessionOwner(session: SessionContext, auth: McpAuthInfo): boolean {
    return session.auth.userId === auth.userId;
  }

  // 仅在非 stateless 模式下启动会话清理定时器
  if (!statelessOnly) {
    const sessionCleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [id, ctx] of sessions) {
        if (
          now - ctx.createdAt > SESSION_TTL ||
          now - ctx.lastActivityAt > SESSION_IDLE
        ) {
          cleanupSession(id);
        }
      }
    }, 60_000);
    sessionCleanupTimer.unref?.();

    // 定期清理 OAuth 过期数据
    const oauthCleanupTimer = setInterval(async () => {
      try {
        await cleanupOAuthArtifactsTransactionally();
      } catch (err) {
        console.error(
          '[OAuth cleanup] failed:',
          err instanceof Error ? err.message : err,
        );
      }
    }, 6 * 60 * 60 * 1000);
    oauthCleanupTimer.unref?.();
  }

  // ─── MCP 路由处理 ───

  const handleMcpPost: express.RequestHandler = async (req, res) => {
    const auth = req.mcpAuth!;

    if (statelessOnly) {
      await handleStatelessRequest(req, res, auth, req.body);
      return;
    }

    const sessionId = getSessionIdHeader(req);

    if (sessionId) {
      const existing = sessions.get(sessionId);
      if (!existing) {
        return res.status(404).json({ error: 'Session not found' });
      }
      if (!isSessionOwner(existing, auth)) {
        return res.status(403).json({ error: 'Session does not belong to current user' });
      }
      existing.lastActivityAt = Date.now();
      await existing.transport.handleRequest(req, res, req.body);
      return;
    }

    if (!isInitializeRequest(req.body)) {
      await handleStatelessRequest(req, res, auth, req.body);
      return;
    }

    if (sessions.size >= MAX_TOTAL_SESSIONS) {
      return res.status(503).json({ error: 'Server at capacity, try again later' });
    }

    const server = createMcpServer(auth);
    const now = Date.now();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (initializedSessionId) => {
        sessions.set(initializedSessionId, {
          server,
          transport,
          auth,
          createdAt: now,
          lastActivityAt: now,
        });
      },
      onsessionclosed: (closedSessionId) => {
        cleanupSession(closedSessionId);
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) cleanupSession(transport.sessionId);
    };
    transport.onerror = () => {
      if (transport.sessionId) cleanupSession(transport.sessionId);
    };

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      if (transport.sessionId) sessions.delete(transport.sessionId);
      await server.close().catch(() => {});
      if (!res.headersSent) {
        return res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
      throw error;
    }
  };

  const handleMcpGet: express.RequestHandler = async (req, res) => {
    const auth = req.mcpAuth!;

    if (statelessOnly) {
      await handleStatelessRequest(req, res, auth);
      return;
    }

    const sessionId = getSessionIdHeader(req);
    if (!sessionId) {
      await handleStatelessRequest(req, res, auth);
      return;
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    if (!isSessionOwner(session, auth)) {
      return res.status(403).json({ error: 'Session does not belong to current user' });
    }
    session.lastActivityAt = Date.now();
    await session.transport.handleRequest(req, res);
  };

  const handleMcpDelete: express.RequestHandler = async (req, res) => {
    const auth = req.mcpAuth!;

    if (statelessOnly) {
      return res.status(400).json({ error: 'Session management not supported in stateless mode' });
    }

    const sessionId = getSessionIdHeader(req);
    if (!sessionId) {
      return res.status(400).json({ error: 'Missing mcp-session-id header' });
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    if (!isSessionOwner(session, auth)) {
      return res.status(403).json({ error: 'Session does not belong to current user' });
    }

    await session.transport.handleRequest(req, res, req.body);
  };

  // ─── 注册 MCP 路由 ───
  app.post(
    ['/', '/mcp'],
    originValidationMiddleware,
    hostValidationMiddleware,
    mcpAuth,
    rateLimitMiddleware,
    handleMcpPost,
  );
  app.get(
    ['/', '/mcp'],
    originValidationMiddleware,
    hostValidationMiddleware,
    mcpAuth,
    rateLimitMiddleware,
    sseConnectionLimitMiddleware,
    handleMcpGet,
  );
  app.delete(
    ['/', '/mcp'],
    originValidationMiddleware,
    hostValidationMiddleware,
    mcpAuth,
    rateLimitMiddleware,
    handleMcpDelete,
  );

  return app;
}
