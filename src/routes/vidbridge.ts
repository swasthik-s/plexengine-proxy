import {
  setResponseHeaders,
  getQuery,
  sendError,
  createError,
  defineEventHandler,
  isPreflightRequest,
  handleCors,
  getRequestHost,
  getRequestProtocol
} from 'h3';
import crypto from 'crypto-js';

// Check if caching is disabled via environment variable
const isCacheDisabled = () => process.env.DISABLE_CACHE === 'true';

// URL obfuscation configuration
const STREAM_SECRET_KEY = process.env.STREAM_SECRET_KEY || 'vidninja-secret-key-change-this';

interface StreamToken {
  url: string;
  expires: number;
  headers?: Record<string, string>;
}

interface CacheEntry {
  data: Uint8Array;
  headers: Record<string, string>;
  timestamp: number;
}

const CACHE_MAX_SIZE = 2000;
const CACHE_EXPIRY_MS = 2 * 60 * 60 * 1000;
const segmentCache: Map<string, CacheEntry> = new Map();

/**
 * Decrypt an obfuscated stream token
 */
function decryptStreamToken(token: string): StreamToken | null {
  try {
    // Check if it's a simple base64 token (fallback for compatibility)
    if (!token.includes('U2FsdGVkX1')) {
      try {
        // Try simple base64 decode
        const restored = token.replace(/-/g, '+').replace(/_/g, '/');
        const padded = restored + '=='.substring(0, (4 - (restored.length % 4)) % 4);
        const decoded = JSON.parse(atob(padded));

        if (decoded.u && decoded.e) {
          return {
            url: decoded.u,
            expires: decoded.e,
            headers: decoded.h
          };
        }
      } catch {
        // Not a simple token, continue to AES decryption
      }
    }

    // AES decryption for fully encrypted tokens
    const base64Token = token.replace(/-/g, '+').replace(/_/g, '/');
    const paddedToken = base64Token + '=='.substring(0, (4 - (base64Token.length % 4)) % 4);

    let decrypted: string;
    try {
      decrypted = crypto.AES.decrypt(atob(paddedToken), STREAM_SECRET_KEY).toString(crypto.enc.Utf8);
    } catch {
      // Try direct decryption without base64 decode
      decrypted = crypto.AES.decrypt(paddedToken, STREAM_SECRET_KEY).toString(crypto.enc.Utf8);
    }

    const tokenData: StreamToken = JSON.parse(decrypted);

    // Check expiration
    if (Date.now() > tokenData.expires) {
      console.log('Token expired');
      return null;
    }

    return tokenData;
  } catch (error) {
    console.error('Failed to decrypt token:', error);
    return null;
  }
}

/**
 * Create an obfuscated stream token
 */
function createStreamToken(url: string, headers?: Record<string, string>, ttlMinutes = 60): string {
  const token: StreamToken = {
    url,
    expires: Date.now() + (ttlMinutes * 60 * 1000),
    headers
  };

  // Encrypt the token
  const encrypted = crypto.AES.encrypt(JSON.stringify(token), STREAM_SECRET_KEY).toString();

  // Make URL-safe
  const urlSafeToken = btoa(encrypted)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return urlSafeToken;
}

function parseURL(req_url: string, baseUrl?: string) {
  if (baseUrl) {
    return new URL(req_url, baseUrl).href;
  }

  const match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);

  if (!match) {
    return null;
  }

  if (!match[1]) {
    if (/^https?:/i.test(req_url)) {
      return null;
    }

    // Scheme is omitted
    if (req_url.lastIndexOf("//", 0) === -1) {
      // "//" is omitted
      req_url = "//" + req_url;
    }
    req_url = (match[4] === "443" ? "https:" : "http:") + req_url;
  }

  try {
    const parsed = new URL(req_url);
    if (!parsed.hostname) {
      // "http://:1/" and "http:/notenoughslashes" could end up here
      return null;
    }
    return parsed.href;
  } catch (error) {
    return null;
  }
}

function cleanupCache() {
  const now = Date.now();
  let expiredCount = 0;

  for (const [url, entry] of segmentCache.entries()) {
    if (now - entry.timestamp > CACHE_EXPIRY_MS) {
      segmentCache.delete(url);
      expiredCount++;
    }
  }

  if (segmentCache.size > CACHE_MAX_SIZE) {
    const entries = Array.from(segmentCache.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);

    const toRemove = entries.slice(0, segmentCache.size - CACHE_MAX_SIZE);
    for (const [url] of toRemove) {
      segmentCache.delete(url);
    }

    console.log(`Cache size limit reached. Removed ${toRemove.length} oldest entries. Current size: ${segmentCache.size}`);
  }

  if (expiredCount > 0) {
    console.log(`Cleaned up ${expiredCount} expired cache entries. Current size: ${segmentCache.size}`);
  }

  return segmentCache.size;
}

let cleanupInterval: any = null;
function startCacheCleanupInterval() {
  if (!cleanupInterval) {
    cleanupInterval = setInterval(cleanupCache, 30 * 60 * 1000);
    console.log('Started periodic cache cleanup interval');
  }
}

startCacheCleanupInterval();

async function prefetchSegment(url: string, headers: HeadersInit) {
  // Skip prefetching if cache is disabled
  if (isCacheDisabled()) {
    return;
  }

  if (segmentCache.size >= CACHE_MAX_SIZE) {
    cleanupCache();
  }

  const existing = segmentCache.get(url);
  const now = Date.now();
  if (existing && (now - existing.timestamp <= CACHE_EXPIRY_MS)) {
    return;
  }

  try {
    const response = await globalThis.fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
        ...(headers as HeadersInit),
      }
    });

    if (!response.ok) {
      console.error(`Failed to prefetch TS segment: ${response.status} ${response.statusText}`);
      return;
    }

    const data = new Uint8Array(await response.arrayBuffer());

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    segmentCache.set(url, {
      data,
      headers: responseHeaders,
      timestamp: Date.now()
    });

    console.log(`Prefetched and cached segment: ${url}`);
  } catch (error) {
    console.error(`Error prefetching segment ${url}:`, error);
  }
}

export function getCachedSegment(url: string) {
  // Return undefined immediately if cache is disabled
  if (isCacheDisabled()) {
    return undefined;
  }

  const entry = segmentCache.get(url);
  if (entry) {
    if (Date.now() - entry.timestamp > CACHE_EXPIRY_MS) {
      segmentCache.delete(url);
      return undefined;
    }
    return entry;
  }
  return undefined;
}

export function getCacheStats() {
  const sizes = Array.from(segmentCache.values())
    .map(entry => entry.data.byteLength);

  const totalBytes = sizes.reduce((sum, size) => sum + size, 0);
  const avgBytes = sizes.length > 0 ? totalBytes / sizes.length : 0;

  return {
    entries: segmentCache.size,
    totalSizeMB: (totalBytes / (1024 * 1024)).toFixed(2),
    avgEntrySizeKB: (avgBytes / 1024).toFixed(2),
    maxSize: CACHE_MAX_SIZE,
    expiryHours: CACHE_EXPIRY_MS / (60 * 60 * 1000)
  };
}

/**
 * Handle obfuscated stream requests - NEW ENDPOINT
 */
async function handleObfuscatedStream(event: any) {
  const token = getQuery(event).token as string;

  if (!token) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'Token parameter is required'
    }));
  }

  console.log(`[vidbridge] Processing obfuscated stream request with token: ${token.substring(0, 20)}...`);

  // Decrypt the token
  const streamData = decryptStreamToken(token);
  if (!streamData) {
    return sendError(event, createError({
      statusCode: 401,
      statusMessage: 'Invalid or expired token'
    }));
  }

  console.log(`[vidbridge] Decrypted URL: ${streamData.url}`);
  console.log(`[vidbridge] Token headers:`, streamData.headers);

  // Use the decrypted URL and headers to proxy the M3U8
  const mockEvent = {
    ...event,
    query: {
      url: streamData.url,
      headers: streamData.headers ? JSON.stringify(streamData.headers) : undefined
    }
  };

  return await proxyM3U8(mockEvent);
}

/**
 * Proxies m3u8 files and replaces the content to point to the proxy
 */
async function proxyM3U8(event: any) {
  const url = getQuery(event).url as string;
  const headersParam = getQuery(event).headers as string;

  if (!url) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'URL parameter is required'
    }));
  }

  let headers = {};
  try {
    headers = headersParam ? JSON.parse(headersParam) : {};
  } catch (e) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'Invalid headers format'
    }));
  }

  try {
    console.log(`[vidbridge] Processing request for URL: ${url}`);
    console.log(`[vidbridge] Headers param: ${headersParam}`);
    console.log(`[vidbridge] Parsed headers:`, headers);

    const response = await globalThis.fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
        ...(headers as HeadersInit),
      }
    });

    console.log(`[vidbridge] Response status: ${response.status} ${response.statusText}`);
    console.log(`[vidbridge] Response headers:`, Object.fromEntries(response.headers.entries()));

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      console.error(`Failed to fetch M3U8: ${response.status} ${response.statusText} for URL: ${url}`);
      console.error(`Response body: ${errorText}`);

      return sendError(event, createError({
        statusCode: response.status,
        statusMessage: `Upstream M3U8 error: ${response.status} ${response.statusText}. URL: ${url}. This might indicate the stream URL has expired or is not accessible.`
      }));
    }

    const m3u8Content = await response.text();
    console.log(`[vidbridge] M3U8 content length: ${m3u8Content.length}`);
    console.log(`[vidbridge] M3U8 content preview: ${m3u8Content.substring(0, 200)}`);

    // Get the base URL for the host
    const host = getRequestHost(event);
    const proto = getRequestProtocol(event);
    const baseProxyUrl = `${proto}://${host}`;

    console.log(`[vidbridge] Base proxy URL: ${baseProxyUrl}`);

    if (m3u8Content.includes("RESOLUTION=")) {
      // This is a master playlist with multiple quality variants
      const lines = m3u8Content.split("\n");
      const newLines: string[] = [];

      for (const line of lines) {
        if (line.startsWith("#")) {
          if (line.startsWith("#EXT-X-KEY:")) {
            // Proxy the key URL
            const regex = /https?:\/\/[^\""\s]+/g;
            const keyUrl = regex.exec(line)?.[0];
            if (keyUrl) {
              // Create obfuscated token for the key URL
              const keyToken = createStreamToken(keyUrl, headers as Record<string, string>, 60);
              const proxyKeyUrl = `${baseProxyUrl}/ts-proxy?token=${keyToken}`;
              newLines.push(line.replace(keyUrl, proxyKeyUrl));
            } else {
              newLines.push(line);
            }
          } else if (line.startsWith("#EXT-X-MEDIA:")) {
            // Proxy alternative media URLs (like audio streams)
            const regex = /https?:\/\/[^\""\s]+/g;
            const mediaUrl = regex.exec(line)?.[0];
            if (mediaUrl) {
              // Create obfuscated token for the media URL
              const mediaToken = createStreamToken(mediaUrl, headers as Record<string, string>, 60);
              const proxyMediaUrl = `${baseProxyUrl}/stream?token=${mediaToken}`;
              newLines.push(line.replace(mediaUrl, proxyMediaUrl));
            } else {
              newLines.push(line);
            }
          } else {
            newLines.push(line);
          }
        } else if (line.trim()) {
          // This is a quality variant URL
          const variantUrl = parseURL(line, url);
          if (variantUrl) {
            // Create obfuscated token for the variant URL
            const variantToken = createStreamToken(variantUrl, headers as Record<string, string>, 60);
            newLines.push(`${baseProxyUrl}/stream?token=${variantToken}`);
          } else {
            newLines.push(line);
          }
        } else {
          // Empty line, preserve it
          newLines.push(line);
        }
      }

      // Set appropriate headers
      setResponseHeaders(event, {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Methods': '*',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });

      return newLines.join("\n");
    } else {
      // This is a media playlist with segments
      const lines = m3u8Content.split("\n");
      const newLines: string[] = [];

      const segmentUrls: string[] = [];

      for (const line of lines) {
        if (line.startsWith("#")) {
          if (line.startsWith("#EXT-X-KEY:")) {
            // Proxy the key URL
            const regex = /https?:\/\/[^\""\s]+/g;
            const keyUrl = regex.exec(line)?.[0];
            if (keyUrl) {
              // Create obfuscated token for the key URL
              const keyToken = createStreamToken(keyUrl, headers as Record<string, string>, 60);
              const proxyKeyUrl = `${baseProxyUrl}/ts-proxy?token=${keyToken}`;
              newLines.push(line.replace(keyUrl, proxyKeyUrl));

              // Only prefetch if cache is enabled
              if (!isCacheDisabled()) {
                prefetchSegment(keyUrl, headers as HeadersInit);
              }
            } else {
              newLines.push(line);
            }
          } else {
            newLines.push(line);
          }
        } else if (line.trim() && !line.startsWith("#")) {
          // This is a segment URL (.ts file)
          const segmentUrl = parseURL(line, url);
          if (segmentUrl) {
            segmentUrls.push(segmentUrl);

            // Create obfuscated token for the segment URL
            const segmentToken = createStreamToken(segmentUrl, headers as Record<string, string>, 60);
            newLines.push(`${baseProxyUrl}/ts-proxy?token=${segmentToken}`);
          } else {
            newLines.push(line);
          }
        } else {
          // Comment or empty line, preserve it
          newLines.push(line);
        }
      }

      if (segmentUrls.length > 0) {
        console.log(`Starting to prefetch ${segmentUrls.length} segments for ${url}`);

        // Only perform cache operations if cache is enabled
        if (!isCacheDisabled()) {
          cleanupCache();

          Promise.all(segmentUrls.map(segmentUrl =>
            prefetchSegment(segmentUrl, headers as HeadersInit)
          )).catch(error => {
            console.error('Error prefetching segments:', error);
          });
        } else {
          console.log('Cache disabled - skipping prefetch operations');
        }
      }

      // Set appropriate headers
      setResponseHeaders(event, {
        'Content-Type': 'application/vnd.apple.mpegurl',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Methods': '*',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      });

      return newLines.join("\n");
    }
  } catch (error: any) {
    console.error('Error proxying M3U8:', error);
    return sendError(event, createError({
      statusCode: 500,
      statusMessage: error.message || 'Error proxying M3U8 file'
    }));
  }
}

/**
 * Handle TS segment proxy requests - Enhanced with token support
 */
async function proxyTsSegment(event: any) {
  const url = getQuery(event).url as string;
  const token = getQuery(event).token as string;
  const headersParam = getQuery(event).headers as string;

  let actualUrl = url;
  let actualHeaders = {};

  // Check if we have a token (obfuscated request)
  if (token) {
    const streamData = decryptStreamToken(token);
    if (!streamData) {
      return sendError(event, createError({
        statusCode: 401,
        statusMessage: 'Invalid or expired token'
      }));
    }
    actualUrl = streamData.url;
    actualHeaders = streamData.headers || {};
  } else if (url) {
    // Traditional URL-based request
    try {
      actualHeaders = headersParam ? JSON.parse(headersParam) : {};
    } catch (e) {
      return sendError(event, createError({
        statusCode: 400,
        statusMessage: 'Invalid headers format'
      }));
    }
  } else {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'URL or token parameter is required'
    }));
  }

  console.log(`[ts-proxy] Processing segment: ${actualUrl}`);

  // Check cache first (if enabled)
  if (!isCacheDisabled()) {
    const cached = getCachedSegment(actualUrl);
    if (cached) {
      console.log(`[ts-proxy] Serving from cache: ${actualUrl}`);

      // Set cached headers
      setResponseHeaders(event, {
        ...cached.headers,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Methods': '*',
      });

      return cached.data;
    }
  }

  try {
    const response = await globalThis.fetch(actualUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0',
        ...(actualHeaders as HeadersInit),
      }
    });

    if (!response.ok) {
      console.error(`Failed to fetch TS segment: ${response.status} ${response.statusText}`);
      return sendError(event, createError({
        statusCode: response.status,
        statusMessage: `Failed to fetch segment: ${response.status} ${response.statusText}`
      }));
    }

    const data = new Uint8Array(await response.arrayBuffer());

    // Prepare response headers
    const responseHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*',
    };

    // Copy relevant headers from the response
    response.headers.forEach((value, key) => {
      if (['content-type', 'content-length', 'cache-control'].includes(key.toLowerCase())) {
        responseHeaders[key] = value;
      }
    });

    setResponseHeaders(event, responseHeaders);

    // Cache the segment if caching is enabled
    if (!isCacheDisabled()) {
      segmentCache.set(actualUrl, {
        data,
        headers: responseHeaders,
        timestamp: Date.now()
      });
    }

    console.log(`[ts-proxy] Served segment: ${actualUrl} (${data.length} bytes)`);
    return data;

  } catch (error: any) {
    console.error('Error proxying TS segment:', error);
    return sendError(event, createError({
      statusCode: 500,
      statusMessage: error.message || 'Error proxying TS segment'
    }));
  }
}

export function handleCacheStats(event: any) {
  cleanupCache();
  setResponseHeaders(event, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache, no-store, must-revalidate'
  });
  return getCacheStats();
}

/**
 * Generate obfuscated URL endpoint - for external use
 */
export function handleCreateToken(event: any) {
  const url = getQuery(event).url as string;
  const headersParam = getQuery(event).headers as string;
  const ttl = parseInt(getQuery(event).ttl as string) || 60;

  if (!url) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'URL parameter is required'
    }));
  }

  let headers = {};
  try {
    headers = headersParam ? JSON.parse(headersParam) : {};
  } catch (e) {
    return sendError(event, createError({
      statusCode: 400,
      statusMessage: 'Invalid headers format'
    }));
  }

  const token = createStreamToken(url, headers as Record<string, string>, ttl);
  const host = getRequestHost(event);
  const proto = getRequestProtocol(event);
  const obfuscatedUrl = `${proto}://${host}/stream?token=${token}`;

  setResponseHeaders(event, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache, no-store, must-revalidate'
  });

  return {
    originalUrl: url,
    obfuscatedUrl,
    token,
    expiresIn: ttl * 60 * 1000,
    expiresAt: Date.now() + (ttl * 60 * 1000)
  };
}

export default defineEventHandler(async (event) => {
  // Handle CORS preflight requests
  if (isPreflightRequest(event)) return handleCors(event, {});

  const pathname = event.path || '';

  // Route requests to appropriate handlers
  if (pathname === '/cache-stats') {
    return handleCacheStats(event);
  } else if (pathname === '/create-token') {
    return handleCreateToken(event);
  } else if (pathname === '/stream') {
    // Handle obfuscated stream requests
    const token = getQuery(event).token as string;
    if (token) {
      return handleObfuscatedStream(event);
    } else {
      // Fallback to regular proxy for backward compatibility
      return await proxyM3U8(event);
    }
  } else if (pathname === '/ts-proxy') {
    return await proxyTsSegment(event);
  } else if (pathname === '/vidbridge' || pathname === '/') {
    // Default endpoint for backward compatibility
    return await proxyM3U8(event);
  }

  return sendError(event, createError({
    statusCode: 404,
    statusMessage: 'Not Found'
  }));
});
