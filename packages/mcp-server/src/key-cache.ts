/**
 * MCP Key 内存验证缓存
 *
 * TTL 1 分钟，避免每次请求都查 DB。
 * 使用惰性淘汰（lazy eviction），兼容 serverless 环境（无 setInterval）。
 */

export interface CachedKeyInfo {
  userId: string;
  keyId: string;
  cachedAt: number;
}

const KEY_CACHE_TTL = 60 * 1000; // 60 秒
const MAX_CACHE_SIZE = 10_000;
const cache = new Map<string, CachedKeyInfo>();

function evictExpiredEntries(now: number) {
  for (const [key, entry] of cache) {
    if (now - entry.cachedAt > KEY_CACHE_TTL) {
      cache.delete(key);
    }
  }
}

export function getCachedKey(keyCode: string): CachedKeyInfo | null {
  const entry = cache.get(keyCode);
  if (!entry) return null;

  if (Date.now() - entry.cachedAt > KEY_CACHE_TTL) {
    cache.delete(keyCode);
    return null;
  }

  return entry;
}

export function setCachedKey(keyCode: string, info: Omit<CachedKeyInfo, 'cachedAt'>): void {
  const now = Date.now();

  if (cache.size >= MAX_CACHE_SIZE && !cache.has(keyCode)) {
    evictExpiredEntries(now);
    // 如果仍然满了，淘汰最旧条目
    if (cache.size >= MAX_CACHE_SIZE) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
  }

  cache.set(keyCode, { ...info, cachedAt: now });
}

export function invalidateCachedKey(keyCode: string): void {
  cache.delete(keyCode);
}
