/**
 * OAuth Token Auto-Refresh for NanoClaw
 *
 * Reads the refresh token from macOS Keychain, calls the Claude OAuth
 * endpoint for a fresh access token, and writes it back to both the
 * Keychain (so Claude CLI stays in sync) and .env (so containers pick it up).
 */
import { execSync } from 'child_process';
import fs from 'fs';
import https from 'https';
import path from 'path';

import { logger } from './logger.js';

// Claude OAuth constants (from Claude Code source)
const TOKEN_URL = 'https://platform.claude.com/v1/oauth/token';
const CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const SCOPES = 'user:profile user:inference user:sessions:claude_code user:mcp_servers';
const KEYCHAIN_SERVICE = 'Claude Code-credentials';
const KEYCHAIN_ACCOUNT = 'default';

// Refresh 10 minutes before expiry
const REFRESH_THRESHOLD_MS = 10 * 60 * 1000;

interface KeychainCredentials {
  claudeAiOauth: {
    accessToken: string;
    refreshToken: string;
    expiresAt: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}

// In-memory cache
let cachedCredentials: KeychainCredentials | null = null;
let refreshInFlight: Promise<string | null> | null = null;

/**
 * Read credentials from macOS Keychain.
 * Returns null on any error (non-macOS, missing item, bad JSON).
 */
export function readKeychainCredentials(): KeychainCredentials | null {
  try {
    const raw = execSync(
      `security find-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w`,
      { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8', timeout: 5000 },
    ).trim();

    const parsed = JSON.parse(raw);
    if (!parsed?.claudeAiOauth?.accessToken || !parsed?.claudeAiOauth?.refreshToken) {
      logger.debug('Keychain credentials missing required OAuth fields');
      return null;
    }
    return parsed as KeychainCredentials;
  } catch {
    logger.debug('Could not read keychain credentials (non-macOS or missing item)');
    return null;
  }
}

/**
 * Write updated credentials back to macOS Keychain.
 * Preserves other top-level keys in the keychain blob.
 */
export function writeKeychainCredentials(updated: KeychainCredentials): boolean {
  try {
    const json = JSON.stringify(updated);
    // security add-generic-password -U updates existing entries.
    // Pass the password via stdin (-w reads from stdin when using -i).
    const hexPassword = Buffer.from(json, 'utf-8').toString('hex');
    execSync(
      `security add-generic-password -U -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -X "${hexPassword}"`,
      { stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 },
    );
    logger.debug('Keychain credentials updated');
    return true;
  } catch (err) {
    logger.warn({ err }, 'Failed to write keychain credentials');
    return false;
  }
}

/**
 * Replace the CLAUDE_CODE_OAUTH_TOKEN line in .env in-place.
 */
export function updateEnvToken(newToken: string): void {
  const envFile = path.join(process.cwd(), '.env');
  try {
    let content = fs.readFileSync(envFile, 'utf-8');
    const pattern = /^CLAUDE_CODE_OAUTH_TOKEN=.*$/m;
    if (pattern.test(content)) {
      content = content.replace(pattern, `CLAUDE_CODE_OAUTH_TOKEN=${newToken}`);
    } else {
      // Append if not present
      content = content.trimEnd() + `\nCLAUDE_CODE_OAUTH_TOKEN=${newToken}\n`;
    }
    fs.writeFileSync(envFile, content);
    logger.debug('Updated .env with new OAuth token');
  } catch (err) {
    logger.warn({ err }, 'Failed to update .env token');
  }
}

/**
 * POST to the Claude OAuth token endpoint for a fresh access token.
 */
export function callRefreshEndpoint(refreshToken: string): Promise<TokenResponse> {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      refresh_token: refreshToken,
      scope: SCOPES,
    }).toString();

    const url = new URL(TOKEN_URL);
    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 15000,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`OAuth refresh failed: HTTP ${res.statusCode} - ${data.slice(0, 200)}`));
            return;
          }
          try {
            resolve(JSON.parse(data) as TokenResponse);
          } catch (err) {
            reject(new Error(`Failed to parse OAuth response: ${err}`));
          }
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('OAuth refresh request timed out'));
    });
    req.write(body);
    req.end();
  });
}

/**
 * Check if the cached token is still fresh (>10 min to expiry).
 */
function isTokenFresh(): boolean {
  if (!cachedCredentials?.claudeAiOauth?.expiresAt) return false;
  const expiresAt = new Date(cachedCredentials.claudeAiOauth.expiresAt).getTime();
  return Date.now() + REFRESH_THRESHOLD_MS < expiresAt;
}

/**
 * Get a valid OAuth token. Returns cached token if fresh, otherwise
 * refreshes from the OAuth endpoint. Deduplicates concurrent calls.
 * Returns null if no keychain credentials are available (falls back to .env).
 */
export async function getValidToken(): Promise<string | null> {
  // No keychain credentials → let caller fall back to .env
  if (!cachedCredentials) return null;

  // Token still fresh → return cached
  if (isTokenFresh()) {
    return cachedCredentials.claudeAiOauth.accessToken;
  }

  // Deduplicate concurrent refresh calls
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      logger.info('OAuth token near expiry, refreshing...');
      const response = await callRefreshEndpoint(cachedCredentials!.claudeAiOauth.refreshToken);

      const newExpiresAt = new Date(Date.now() + response.expires_in * 1000).toISOString();

      // Update cached credentials (preserve other keys)
      cachedCredentials = {
        ...cachedCredentials!,
        claudeAiOauth: {
          ...cachedCredentials!.claudeAiOauth,
          accessToken: response.access_token,
          expiresAt: newExpiresAt,
          ...(response.refresh_token ? { refreshToken: response.refresh_token } : {}),
        },
      };

      // Persist to keychain and .env (best effort)
      writeKeychainCredentials(cachedCredentials);
      updateEnvToken(response.access_token);

      logger.info(
        { expiresAt: newExpiresAt },
        'OAuth token refreshed successfully',
      );
      return response.access_token;
    } catch (err) {
      logger.error({ err }, 'OAuth token refresh failed, using existing token');
      // Return existing (possibly expired) token rather than null
      return cachedCredentials?.claudeAiOauth?.accessToken ?? null;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

/**
 * Read keychain on startup and populate in-memory cache.
 */
export function initOAuthCache(): void {
  cachedCredentials = readKeychainCredentials();
  if (cachedCredentials) {
    const expiresAt = cachedCredentials.claudeAiOauth.expiresAt;
    const remainingMs = new Date(expiresAt).getTime() - Date.now();
    const remainingMin = Math.round(remainingMs / 60000);
    logger.info(
      { expiresAt, remainingMin },
      'OAuth cache initialized from keychain',
    );
  } else {
    logger.info('No keychain OAuth credentials found, using .env token');
  }
}

/**
 * Background timer that proactively refreshes the token before expiry.
 * Returns a cancel function. Timer is .unref()'d so it doesn't block exit.
 */
export function startOAuthRefreshTimer(intervalMs = 5 * 60 * 1000): () => void {
  const timer = setInterval(async () => {
    if (!cachedCredentials) return;
    if (isTokenFresh()) return;
    try {
      await getValidToken();
    } catch (err) {
      logger.warn({ err }, 'Background OAuth refresh failed');
    }
  }, intervalMs);
  timer.unref();

  logger.debug({ intervalMs }, 'OAuth refresh timer started');
  return () => clearInterval(timer);
}

/** @internal — exported for testing */
export function _resetCache(): void {
  cachedCredentials = null;
  refreshInFlight = null;
}
