// ==== IMPORTS ====
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { serveStatic } from '@hono/node-server/serve-static'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import { secureHeaders } from 'hono/secure-headers'
import { cors } from 'hono/cors'
import Stripe from "stripe";
import { compare as legacyBcryptCompare } from "./vendor/legacy-bcrypt.js";
import crypto from "crypto";
import { Client } from "@xdevplatform/xdk";

import { databaseManager } from "./adapters/manager.js";
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, mkdir, stat, readFileSync, writeFileSync, statSync, existsSync, mkdirSync, unlinkSync, readdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';

// ==== PLAYWRIGHT (lazy) — used by /qr/:username/image screenshot route ====
// Loaded on first screenshot request so the server boots without playwright installed.
let playwright = null;
let persistentBrowser = null;
let screenshotCount = 0;
const MAX_SCREENSHOTS_BEFORE_RESTART = 100;

/**
 * Lazily import playwright. Returns null if not installed (feature disabled).
 * @returns {Promise<object|null>} playwright module or null
 */
async function getPlaywright() {
  if (playwright) return playwright;
  try {
    playwright = await import("playwright");
    logger.info('Playwright loaded (lazy)');
    return playwright;
  } catch {
    logger.warn('Playwright not available - screenshot feature disabled');
    return null;
  }
}

/**
 * Close the persistent browser to free memory. Errors are ignored.
 * @returns {Promise<void>}
 */
async function restartBrowser() {
  if (persistentBrowser) {
    try {
      await persistentBrowser.close();
    } catch {
      // Ignore close errors
    }
    persistentBrowser = null;
  }
  screenshotCount = 0;
}

/**
 * Get a healthy persistent WebKit browser instance, launching or restarting as
 * needed for memory management. Returns null if playwright is unavailable.
 * @returns {Promise<object|null>} Browser instance or null
 */
async function getBrowser() {
  const pw = await getPlaywright();
  if (!pw) return null;

  if (screenshotCount >= MAX_SCREENSHOTS_BEFORE_RESTART && persistentBrowser) {
    await restartBrowser();
  }

  if (persistentBrowser?.isConnected()) {
    return persistentBrowser;
  }

  logger.info('Launching persistent WebKit browser');
  persistentBrowser = await pw.webkit.launch({ headless: true });
  return persistentBrowser;
}

// ==== X API CACHE TTLs ====
const PROFILE_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 1 week
const SCREENSHOT_CACHE_TTL = 60 * 60 * 1000; // 1 hour

// ==== X API DAILY RATE LIMIT (cache-miss requests only) ====
// yagni: in-memory per-IP map, swap for shared store if multi-instance
const xApiRateLimitStore = new Map();

/**
 * Extract client IP from x-forwarded-for (rightmost = set by trusted proxy).
 * @param {import('hono').Context} c - Hono context
 * @returns {string} Client IP or 'unknown'
 */
function getClientIP(c) {
  const forwarded = c.req.header('x-forwarded-for');
  if (forwarded) {
    const ips = forwarded.split(',').map(ip => ip.trim());
    return ips[ips.length - 1];
  }
  return 'unknown';
}

// ==== SERVER CONFIG ====
const port = parseInt(process.env.PORT || "8000");

// ==== STRUCTURED LOGGING ====
// Defined early so all code can use it (no external dependencies)
const logger = {
  error: (message, meta = {}) => {
    const logEntry = {
      level: 'ERROR',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.error(!isProd() ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  warn: (message, meta = {}) => {
    const logEntry = {
      level: 'WARN',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.warn(!isProd() ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  info: (message, meta = {}) => {
    const logEntry = {
      level: 'INFO',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.log(!isProd() ? JSON.stringify(logEntry, null, 2) : JSON.stringify(logEntry));
  },

  debug: (message, meta = {}) => {
    if (isProd()) return;
    const logEntry = {
      level: 'DEBUG',
      timestamp: new Date().toISOString(),
      message,
      ...meta
    };
    console.log(JSON.stringify(logEntry, null, 2));
  }
};

// ==== CSRF PROTECTION ====
const csrfTokenStore = new Map(); // userID -> { token, timestamp }
const CSRF_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours
const CSRF_MAX_ENTRIES = 50000; // LRU eviction threshold

/**
 * LRU eviction helper that removes oldest entries when over limit
 *
 * Prevents memory leaks in CSRF store by removing oldest entries based on
 * timestamp when store exceeds maxEntries threshold.
 *
 * @param {Map} store - Map to evict entries from
 * @param {number} maxEntries - Maximum entries before eviction
 * @param {Function} getTimestamp - Function to extract timestamp from value
 * @returns {void}
 */
function evictOldestEntries(store, maxEntries, getTimestamp) {
  if (store.size <= maxEntries) return;

  // Convert to array and sort by timestamp
  const entries = Array.from(store.entries())
    .map(([key, value]) => ({ key, timestamp: getTimestamp(value) }))
    .sort((a, b) => a.timestamp - b.timestamp);

  // Remove oldest entries until under limit
  const toRemove = store.size - maxEntries;
  for (let i = 0; i < toRemove; i++) {
    store.delete(entries[i].key);
  }
}

/**
 * Generate cryptographically secure CSRF token
 *
 * Uses crypto.randomBytes to generate 64-character hex token.
 *
 * @returns {string} Hex-encoded CSRF token
 */
function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * CSRF protection middleware using timing-safe comparison
 *
 * Validates CSRF token from x-csrf-token header against stored token for userID.
 * Skips validation for GET requests and signup/signin routes. Uses timing-safe
 * comparison to prevent timing attacks. Enforces 24-hour token expiry.
 * Auto-regenerates token if missing (e.g., server restart) for authenticated users.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response|void>} 403 error or continues to next middleware
 */
async function csrfProtection(c, next) {
  if (c.req.method === 'GET' || c.req.path === '/api/signup' || c.req.path === '/api/signin') {
    return next();
  }

  const csrfToken = c.req.header('x-csrf-token');
  const userID = c.get('userID'); // Set by authMiddleware

  if (!csrfToken || !userID) {
    logger.info('CSRF validation failed - missing token or userID', {
      hasToken: !!csrfToken,
      hasUserID: !!userID,
      path: c.req.path
    });
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  let storedData = csrfTokenStore.get(userID);
  if (!storedData) {
    // Auto-regenerate token for authenticated users (e.g., after server restart)
    // Security: This block only runs if authMiddleware passed (JWT valid)
    const newToken = generateCSRFToken();
    storedData = { token: newToken, timestamp: Date.now() };
    csrfTokenStore.set(userID, storedData);

    setCookie(c, 'csrf_token', newToken, {
      httpOnly: false,
      secure: isProd(),
      sameSite: 'Lax',
      path: '/',
      maxAge: CSRF_TOKEN_EXPIRY / 1000
    });

    logger.info('CSRF token auto-regenerated after store miss', { userID });
    await next();
    return;
  }

  // Use timing-safe comparison to prevent timing attacks
  const tokenBuffer = Buffer.from(csrfToken);
  const storedBuffer = Buffer.from(storedData.token);
  if (tokenBuffer.length !== storedBuffer.length || !crypto.timingSafeEqual(tokenBuffer, storedBuffer)) {
    logger.info('CSRF validation failed - token mismatch', {
      userID,
      path: c.req.path
    });
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  // Check if token is expired
  if (Date.now() - storedData.timestamp > CSRF_TOKEN_EXPIRY) {
    csrfTokenStore.delete(userID);
    logger.info('CSRF validation failed - token expired', {
      userID,
      age: Math.floor((Date.now() - storedData.timestamp) / 1000) + 's'
    });
    return c.json({ error: 'CSRF token expired' }, 403);
  }

  logger.debug('CSRF validation passed', { userID });
  await next();
}

// Cleanup expired CSRF tokens every hour to prevent memory leak
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;

  for (const [userID, data] of csrfTokenStore.entries()) {
    if (now - data.timestamp > CSRF_TOKEN_EXPIRY) {
      csrfTokenStore.delete(userID);
      cleaned++;
    }
  }

  // LRU eviction if still over limit
  evictOldestEntries(csrfTokenStore, CSRF_MAX_ENTRIES, (data) => data.timestamp);

  if (cleaned > 0) {
    logger.debug('CSRF cleanup completed', { removedTokens: cleaned });
  }
}, 60 * 60 * 1000); // Run every hour

// ==== ACCOUNT LOCKOUT ====
const loginAttemptStore = new Map(); // email -> { attempts, lockedUntil }
const LOCKOUT_THRESHOLD = 5; // Lock after 5 failed attempts
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const LOCKOUT_MAX_ENTRIES = 50000; // LRU eviction threshold

/**
 * Check if account is locked due to failed login attempts
 *
 * @param {string} email - Email address to check
 * @returns {{locked: boolean, remainingTime: number}} Lock status and remaining time in seconds
 */
function isAccountLocked(email) {
  const record = loginAttemptStore.get(email);
  if (!record) return { locked: false, remainingTime: 0 };

  const now = Date.now();
  if (record.lockedUntil && now < record.lockedUntil) {
    return {
      locked: true,
      remainingTime: Math.ceil((record.lockedUntil - now) / 1000)
    };
  }

  // Lock expired, clear record
  if (record.lockedUntil && now >= record.lockedUntil) {
    loginAttemptStore.delete(email);
  }

  return { locked: false, remainingTime: 0 };
}

/**
 * Record a failed login attempt for an email
 *
 * Increments attempt counter. Locks account after LOCKOUT_THRESHOLD failures.
 *
 * @param {string} email - Email address that failed login
 * @returns {void}
 */
function recordFailedLogin(email) {
  const now = Date.now();
  let record = loginAttemptStore.get(email);

  if (!record) {
    record = { attempts: 0, lockedUntil: null };
    loginAttemptStore.set(email, record);
  }

  record.attempts++;

  if (record.attempts >= LOCKOUT_THRESHOLD) {
    record.lockedUntil = now + LOCKOUT_DURATION;
    logger.info('Account locked due to failed attempts', { email: email.substring(0, 3) + '***' });
  }
}

/**
 * Clear failed login attempts on successful login
 *
 * @param {string} email - Email address to clear
 * @returns {void}
 */
function clearFailedLogins(email) {
  loginAttemptStore.delete(email);
}

// Cleanup expired lockout entries every 15 minutes
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;

  for (const [email, record] of loginAttemptStore.entries()) {
    if (record.lockedUntil && now >= record.lockedUntil) {
      loginAttemptStore.delete(email);
      cleaned++;
    }
  }

  // LRU eviction if still over limit
  evictOldestEntries(loginAttemptStore, LOCKOUT_MAX_ENTRIES, (data) => data.lockedUntil || 0);

  if (cleaned > 0) {
    logger.debug('Lockout cleanup completed', { removedEntries: cleaned });
  }
}, 15 * 60 * 1000);

// ==== CONFIG & ENV ====
// Environment setup - MUST happen before config loading
if (!isProd()) {
  loadLocalENV();
} else {
  setInterval(async () => {
    logger.debug('Hourly task completed');
  }, 60 * 60 * 1000); // Every hour
}

/**
 * Resolve environment variable placeholders in configuration strings
 *
 * Replaces ${VAR_NAME} patterns with process.env values. Logs warning
 * and preserves placeholder if environment variable is undefined.
 *
 * @param {string} str - String with ${VAR_NAME} placeholders
 * @returns {string} String with placeholders replaced
 */
function resolveEnvironmentVariables(str) {
  if (typeof str !== 'string') return str;

  return str.replace(/\$\{([^}]+)\}/g, (match, varName) => {
    const envValue = process.env[varName];
    if (envValue === undefined) {
      logger.warn('Environment variable not defined, using placeholder', { varName, placeholder: match });
      return match; // Return the placeholder if env var is not found
    }
    return envValue;
  });
}

// Load and process configuration
let config;
try {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const configPath = resolve(__dirname, './config.json');
  const configData = await promisify(readFile)(configPath);
  const rawConfig = JSON.parse(configData.toString());

  // Resolve environment variables in configuration
  config = {
    staticDir: rawConfig.staticDir || '../dist',
    database: {
      ...rawConfig.database,
      connectionString: resolveEnvironmentVariables(rawConfig.database.connectionString)
    }
  };
} catch (err) {
  logger.error('Failed to load config, using defaults', { error: err.message });
  config = {
    staticDir: '../dist',
    database: {
      db: "MyApp",
      dbType: "sqlite",
      connectionString: "./databases/MyApp.db"
    }
  };
}

const STRIPE_KEY = process.env.STRIPE_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Validate required environment variables are set
 *
 * Checks for STRIPE_KEY, STRIPE_ENDPOINT_SECRET, JWT_SECRET, and any
 * unresolved ${VAR} references in database config. Logs warnings for
 * missing variables but does not exit the process.
 *
 * @returns {boolean} True if all required variables are present
 */
function validateEnvironmentVariables() {
  const missing = [];

  if (!STRIPE_KEY) missing.push('STRIPE_KEY');
  if (!process.env.STRIPE_ENDPOINT_SECRET) missing.push('STRIPE_ENDPOINT_SECRET');
  if (!JWT_SECRET) missing.push('JWT_SECRET');

  // Check for database environment variables that are referenced but not defined
  if (typeof config.database.connectionString === 'string') {
    const matches = config.database.connectionString.match(/\$\{([^}]+)\}/g);
    if (matches) {
      matches.forEach(match => {
        const varName = match.slice(2, -1); // Remove ${ and }
        if (!process.env[varName]) {
          missing.push(`${varName} (referenced in database config)`);
        }
      });
    }
  }

  if (missing.length > 0) {
    logger.warn('Missing environment variables - server continuing with limited functionality', {
      missing,
      hint: 'Set DATABASE_URL, MONGODB_URL, POSTGRES_URL, STRIPE_KEY, JWT_SECRET for full functionality'
    });

    // Don't exit - let the server continue with warnings
    return false;
  }

  return true;
}

const envValidationPassed = validateEnvironmentVariables();

if (envValidationPassed) {
  logger.info('Environment variables validated successfully');
}

logger.info('Single-client backend initialized');

// ==== DATABASE CONFIG ====
// Single database configuration - no origin-based routing needed
const dbConfig = config.database;

// ==== SERVICES SETUP ====
// Stripe setup (only if key is available)
let stripe = null;
if (STRIPE_KEY) {
  stripe = new Stripe(STRIPE_KEY);
} else {
  logger.warn('STRIPE_KEY not set - Stripe functionality disabled');
}

// X API client (env: X_BEARER_TOKEN). Degrades to 503 on /user/:username if unset.
const X_BEARER_TOKEN = process.env.X_BEARER_TOKEN;
let xClient = null;
if (X_BEARER_TOKEN) {
  xClient = new Client({ bearerToken: X_BEARER_TOKEN });
} else {
  logger.warn('X_BEARER_TOKEN not set - X API functionality disabled');
}

// Single database config - always use the same one
const currentDbConfig = dbConfig;

/**
 * Database helper with pre-bound configuration
 *
 * Provides shorthand methods for database operations without repeating
 * dbType, db, connectionString on every call.
 *
 * @type {Object}
 * @example
 * // Instead of:
 * await db.findUser( { email });
 * // Use:
 * await db.findUser({ email });
 */
const db = {
  findUser: (query, projection) => databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, query, projection),
  insertUser: (userData) => databaseManager.insertUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, userData),
  updateUser: (query, update) => databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, query, update),
  findAuth: (query) => databaseManager.findAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, query),
  insertAuth: (authData) => databaseManager.insertAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, authData),
  updateAuth: (query, update) => databaseManager.updateAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, query, update),
  findWebhookEvent: (eventId) => databaseManager.findWebhookEvent(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, eventId),
  insertWebhookEvent: (eventId, eventType, processedAt) => databaseManager.insertWebhookEvent(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, eventId, eventType, processedAt),
  executeQuery: (queryObject) => databaseManager.executeQuery(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, queryObject)
};

// ==== HONO SETUP ====
const app = new Hono();

// Get __dirname for static file serving
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ==== DISK IMAGE CACHE (cached avatar/banner images from X) ====
const IMAGE_CACHE_DIR = resolve(__dirname, './cache');
if (!existsSync(IMAGE_CACHE_DIR)) {
  mkdirSync(IMAGE_CACHE_DIR, { recursive: true });
}

/**
 * Remove disk-cached images older than PROFILE_CACHE_TTL (best-effort).
 * @returns {void}
 */
function cleanExpiredDiskCache() {
  try {
    const files = readdirSync(IMAGE_CACHE_DIR);
    const now = Date.now();
    let deleted = 0;
    for (const file of files) {
      const filePath = resolve(IMAGE_CACHE_DIR, file);
      try {
        const stats = statSync(filePath);
        if (now - stats.mtimeMs > PROFILE_CACHE_TTL) {
          unlinkSync(filePath);
          deleted++;
        }
      } catch {
        // Ignore stat/unlink errors
      }
    }
    if (deleted > 0) logger.debug('Disk cache cleanup', { removed: deleted });
  } catch (err) {
    logger.error('Disk cache cleanup error', { error: err.message });
  }
}

/**
 * Download an image from an allowlisted X CDN host and cache it to disk.
 * @param {string|null} imageUrl - Source image URL (must be pbs/abs.twimg.com)
 * @param {string} cacheId - Cache key / filename stem
 * @returns {Promise<string|null>} cacheId on success, null on failure/blocked
 */
async function cacheImage(imageUrl, cacheId) {
  if (!imageUrl) return null;
  try {
    const parsed = new URL(imageUrl);
    if (!['pbs.twimg.com', 'abs.twimg.com'].includes(parsed.hostname)) {
      logger.warn('Blocked image fetch to non-X domain', { host: parsed.hostname });
      return null;
    }
    const response = await fetch(imageUrl);
    if (!response.ok) return null;
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    const ext = contentType.includes('png') ? 'png' : 'jpg';
    const buffer = Buffer.from(await response.arrayBuffer());
    const filePath = resolve(IMAGE_CACHE_DIR, `${cacheId}.${ext}`);
    await writeFile(filePath, buffer);
    return cacheId;
  } catch (err) {
    logger.error('Failed to cache image', { cacheId, error: err.message });
    return null;
  }
}

// Daily cache hygiene: purge expired SQLite + disk caches
setInterval(async () => {
  try {
    const deletedProfiles = await databaseManager.cleanExpiredProfiles(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, PROFILE_CACHE_TTL
    );
    if (deletedProfiles > 0) logger.debug('Expired profiles purged', { count: deletedProfiles });

    const deletedImages = await databaseManager.cleanExpiredImages(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, SCREENSHOT_CACHE_TTL
    );
    if (deletedImages > 0) logger.debug('Expired screenshots purged', { count: deletedImages });

    cleanExpiredDiskCache();
  } catch (err) {
    logger.error('Cache cleanup error', { error: err.message });
  }
}, 24 * 60 * 60 * 1000);

// CORS middleware (needed for development when frontend is on different port)
// Use CORS_ORIGINS env var in production, fallback to localhost for development
const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:5173', 'http://localhost:8000', 'http://127.0.0.1:5173', 'http://127.0.0.1:8000'];

app.use('*', cors({
  origin: corsOrigins,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
  credentials: true
}));

// Apache Common Log Format middleware
app.use('*', async (c, next) => {
  const start = Date.now();
  await next();
  const timestamp = new Date().toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
  const method = c.req.method;
  const url = c.req.path;
  const status = c.res.status;
  const duration = Date.now() - start;

  console.log(`[${timestamp}] "${method} ${url}" ${status} (${duration}ms)`);
});

// Security headers middleware
app.use('*', secureHeaders({
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "https:"],
    fontSrc: ["'self'"],
    connectSrc: ["'self'"],
    frameAncestors: ["'none'"]
  },
  strictTransportSecurity: !isProd() ? false : 'max-age=31536000; includeSubDomains; preload',
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    payment: []
  }
}));

// Request logging middleware (dev only)
app.use('*', async (c, next) => {
  if (!isProd()) {
    const requestId = Math.random().toString(36).substr(2, 9);
    logger.debug('Request received', { method: c.req.method, path: c.req.path, requestId });
  }
  await next();
});

const tokenExpirationDays = 30;

const scryptAsync = promisify(crypto.scrypt);
const SCRYPT_KEYLEN = 64;
const SCRYPT_SALTLEN = 16;

/**
 * Hash password using node:crypto scrypt
 *
 * Format: `scrypt$<base64url salt>$<base64url key>`. New hashes always use
 * scrypt; legacy bcrypt hashes (prefix `$2`) are verified via the dispatch
 * in verifyPassword but never created.
 *
 * @async
 * @param {string} password - Plain text password to hash
 * @returns {Promise<string>} Scrypt hash string
 */
async function hashPassword(password) {
  const salt = crypto.randomBytes(SCRYPT_SALTLEN);
  const key = await scryptAsync(password, salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

/**
 * Verify password against stored hash (scrypt or legacy bcrypt)
 *
 * Dispatches on stored hash prefix: `scrypt$` → native scrypt verify;
 * `$2` → bcryptjs (legacy users predating the scrypt migration).
 *
 * @async
 * @param {string} password - Plain text password to verify
 * @param {string} stored - Stored hash (scrypt or bcrypt format)
 * @returns {Promise<boolean>} True if password matches stored hash
 */
async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  if (stored.startsWith('scrypt$')) {
    const [, saltB64, keyB64] = stored.split('$');
    const salt = Buffer.from(saltB64, 'base64url');
    const expected = Buffer.from(keyB64, 'base64url');
    const candidate = await scryptAsync(password, salt, SCRYPT_KEYLEN);
    return expected.length === candidate.length && crypto.timingSafeEqual(expected, candidate);
  }
  if (stored.startsWith('$2')) {
    return await legacyBcryptCompare(password, stored);
  }
  return false;
}

/**
 * Whether a stored hash should be migrated to scrypt on next successful login
 *
 * @param {string} stored - Stored hash
 * @returns {boolean} True if the hash is in legacy bcrypt format
 */
function needsRehash(stored) {
  return typeof stored === 'string' && !stored.startsWith('scrypt$');
}

/**
 * Calculate JWT expiration timestamp
 *
 * @returns {number} Unix timestamp 30 days in the future
 */
function tokenExpireTimestamp(){
  return Math.floor(Date.now() / 1000) + tokenExpirationDays * 24 * 60 * 60; // 30 days from now
}

/**
 * Sign an HS256 JWT using node:crypto HMAC-SHA256
 *
 * Produces a token byte-compatible with jsonwebtoken: header
 * {"alg":"HS256","typ":"JWT"} followed by the payload, joined and signed
 * over `base64url(header).base64url(payload)`.
 *
 * @param {Object} payload - Payload to encode (must include exp)
 * @param {string} secret - HMAC signing secret
 * @returns {string} Compact JWT string
 */
function jwtSign(payload, secret) {
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
}

/**
 * Verify an HS256 JWT and return its payload
 *
 * Compatible with tokens issued by jsonwebtoken (same algorithm, same secret).
 * Throws an Error with name === 'TokenExpiredError' for expired tokens, or a
 * generic Error for malformed/invalid signatures.
 *
 * @param {string} token - JWT string to verify
 * @param {string} secret - HMAC verification secret
 * @returns {Object} Decoded payload
 * @throws {Error} If token is malformed, signature invalid, or expired
 */
function jwtVerify(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const [head, body, sig] = parts;
  if (!head || !body || !sig) throw new Error('Invalid token');
  const expected = crypto.createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    throw new Error('Invalid signature');
  }
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
    const err = new Error('Token expired');
    err.name = 'TokenExpiredError';
    throw err;
  }
  return payload;
}

/**
 * Generate JWT token for user authentication
 *
 * Creates HS256-signed JWT with 30-day expiration. Requires JWT_SECRET
 * environment variable.
 *
 * @async
 * @param {string} userID - User ID to encode in token
 * @returns {Promise<string>} Signed JWT token
 * @throws {Error} If JWT_SECRET not configured or signing fails
 */
async function generateToken(userID) {
  try {
    if (!JWT_SECRET) {
      throw new Error("JWT_SECRET not configured - authentication disabled");
    }

    const exp = tokenExpireTimestamp();
    const payload = { userID, exp };

    return jwtSign(payload, JWT_SECRET);
  } catch (error) {
    logger.error('Token generation error', { error: error.message });
    throw error;
  }
}

/**
 * Authentication middleware using JWT from HttpOnly cookie
 *
 * Verifies JWT token from 'token' cookie. Sets userID in context on success,
 * normalized to string for consistent Map key usage across middleware (CSRF, sessions).
 * Returns 401 for missing, expired, or invalid tokens. Returns 503 if
 * JWT_SECRET not configured.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {Function} next - Next middleware function
 * @returns {Promise<Response|void>} 401/503 error or continues to next middleware
 */
async function authMiddleware(c, next) {
  if (!JWT_SECRET) {
    return c.json({ error: "Authentication service unavailable" }, 503);
  }

  // Read token from HttpOnly cookie
  const token = getCookie(c, 'token');
  if (!token) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    const payload = jwtVerify(token, JWT_SECRET);
    // Normalize userID to string for consistent Map key usage (CSRF, sessions)
    const normalizedUserID = String(payload.userID);
    c.set('userID', normalizedUserID);
    await next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      logger.debug('Token expired');
      return c.json({ error: "Token expired" }, 401);
    }
    logger.error('Token verification error', { error: error.message });
    return c.json({ error: "Invalid token" }, 401);
  }
}

/**
 * Generate RFC 4122 compliant UUID v4
 *
 * Uses crypto.randomUUID() for cryptographically secure unique identifiers.
 *
 * @returns {string} UUID string
 */
function generateUUID() {
  return crypto.randomUUID();
}

/**
 * Escape HTML special characters to prevent XSS attacks
 *
 * Replaces &, <, >, ", ', / with HTML entities. Returns original value
 * if not a string.
 *
 * @param {string} text - Text to escape
 * @returns {string} HTML-escaped text
 */
const escapeHtml = (text) => {
  if (typeof text !== 'string') return text;
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  };
  return text.replace(/[&<>"'/]/g, (char) => map[char]);
};

/**
 * Validate email address format and length
 *
 * RFC 5321 compliant validation with robust regex checking local part,
 * domain, and TLD. Max length 254 characters. Prevents consecutive dots
 * and leading/trailing hyphens.
 *
 * @param {string} email - Email address to validate
 * @returns {boolean} True if valid email format
 */
const validateEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false; // RFC 5321

  // More robust email validation:
  // - Local part: letters, numbers, and common special chars (no consecutive dots)
  // - Domain: letters, numbers, hyphens (no consecutive dots or leading/trailing hyphens)
  // - TLD: 2-63 characters
  const emailRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}$/;
  return emailRegex.test(email);
};

/**
 * Validate password length within bcrypt limits
 *
 * Enforces 6-72 character range (bcrypt's maximum is 72 bytes).
 *
 * @param {string} password - Password to validate
 * @returns {boolean} True if valid password length
 */
const validatePassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  if (password.length < 6 || password.length > 72) return false; // bcrypt limit
  return true;
};

/**
 * Validate name length and non-empty after trim
 *
 * Enforces 1-100 character range after trimming whitespace.
 *
 * @param {string} name - Name to validate
 * @returns {boolean} True if valid name
 */
const validateName = (name) => {
  if (!name || typeof name !== 'string') return false;
  if (name.trim().length === 0 || name.length > 100) return false;
  return true;
};

/**
 * Set authentication cookies and generate CSRF token for user session
 *
 * Creates CSRF token, stores it in memory, and sets both JWT (HttpOnly) and
 * CSRF (readable) cookies. Consolidates duplicate cookie logic from signup/signin.
 *
 * @async
 * @param {Context} c - Hono context
 * @param {string} userID - User ID to associate with session
 * @param {string} jwtToken - Pre-generated JWT token
 * @returns {string} Generated CSRF token
 */
function setAuthCookies(c, userID, jwtToken) {
  const csrfToken = generateCSRFToken();
  csrfTokenStore.set(userID.toString(), { token: csrfToken, timestamp: Date.now() });

  // Set HttpOnly JWT cookie
  setCookie(c, 'token', jwtToken, {
    httpOnly: true,
    secure: isProd(),
    sameSite: 'Strict',
    path: '/',
    maxAge: tokenExpirationDays * 24 * 60 * 60
  });

  // Set CSRF token cookie (readable by frontend)
  setCookie(c, 'csrf_token', csrfToken, {
    httpOnly: false,
    secure: isProd(),
    sameSite: 'Lax',
    path: '/',
    maxAge: CSRF_TOKEN_EXPIRY / 1000
  });

  return csrfToken;
}

// ==== STRIPE WEBHOOK (raw body needed) ====

/**
 * Resolve a Stripe customer ID to a normalized lowercase email.
 *
 * @param {string} stripeID - Stripe customer ID
 * @returns {Promise<string|null>} Normalized email, or null if missing
 */
async function resolveCustomerEmail(stripeID) {
  const customer = await stripe.customers.retrieve(stripeID);
  if (!customer?.email) {
    logger.warn('Webhook: Customer has no email', { stripeID });
    return null;
  }
  return customer.email.toLowerCase();
}

/**
 * Build the canonical user.subscription patch from a Stripe customer ID
 * and a Stripe subscription object.
 *
 * @param {string} stripeID - Stripe customer ID
 * @param {object} stripeSub - Stripe subscription object
 * @returns {{stripeID: string, expires: number, status: string}}
 */
function buildSubscriptionPatch(stripeID, stripeSub) {
  return {
    stripeID,
    expires: stripeSub.current_period_end,
    status: stripeSub.status
  };
}

/**
 * Apply a $set patch to the user identified by email. Returns false if no
 * matching user is found (silent no-op so Stripe will not retry).
 *
 * @param {string} email - Normalized email
 * @param {object} $set - MongoDB-style $set fields
 * @returns {Promise<boolean>} True if a user was patched
 */
async function applyUserPatch(email, $set) {
  const user = await db.findUser({ email });
  if (!user) {
    logger.warn('Webhook: No user found for email', { email });
    return false;
  }
  await db.updateUser({ email }, { $set });
  return true;
}

app.post("/api/payment", async (c) => {
  logger.info('Payment webhook received');

  const signature = c.req.header("stripe-signature");
  const rawBody = await c.req.arrayBuffer();
  const body = Buffer.from(rawBody);

  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, signature, process.env.STRIPE_ENDPOINT_SECRET);
    logger.debug('Webhook event received', { type: event.type });
  } catch (e) {
    logger.error('Webhook signature verification failed', { error: e.message });
    return c.body(null, 400);
  }

  try {
    // Idempotency check - skip if already processed
    const existingEvent = await db.findWebhookEvent(event.id);
    if (existingEvent) {
      logger.info('Webhook event already processed, skipping', { eventId: event.id });
      return c.body(null, 200);
    }

    // Record event BEFORE processing to prevent race conditions
    await db.insertWebhookEvent(event.id, event.type, Date.now());

    const eventObject = event.data.object;

    if (["customer.subscription.deleted", "customer.subscription.updated", "customer.subscription.created"].includes(event.type)) {
      const { customer: stripeID, current_period_end, status } = eventObject;
      if (!stripeID) {
        logger.error('Webhook missing customer ID', { type: event.type });
        return c.body(null, 400);
      }
      const email = await resolveCustomerEmail(stripeID);
      if (!email) return c.body(null, 400);
      const ok = await applyUserPatch(email, { subscription: { stripeID, expires: current_period_end, status } });
      if (ok) logger.info('Subscription updated', { type: event.type, email, status });
    }

    if (event.type === "checkout.session.completed") {
      const { customer: stripeID, customer_email, subscription: subscriptionId } = eventObject;
      if (subscriptionId && stripeID) {
        const [subscription, email] = await Promise.all([
          stripe.subscriptions.retrieve(subscriptionId),
          customer_email ? Promise.resolve(customer_email.toLowerCase()) : resolveCustomerEmail(stripeID)
        ]);
        if (email) {
          const ok = await applyUserPatch(email, { subscription: buildSubscriptionPatch(stripeID, subscription) });
          if (ok) logger.info('Checkout completed', { email, status: subscription.status });
        }
      }
    }

    if (event.type === "invoice.paid") {
      const { customer: stripeID, subscription: subscriptionId } = eventObject;
      if (subscriptionId && stripeID) {
        const [subscription, email] = await Promise.all([
          stripe.subscriptions.retrieve(subscriptionId),
          resolveCustomerEmail(stripeID)
        ]);
        if (email) {
          const ok = await applyUserPatch(email, { subscription: buildSubscriptionPatch(stripeID, subscription) });
          if (ok) logger.info('Invoice paid', { email });
        }
      }
    }

    if (event.type === "invoice.payment_failed") {
      const { customer: stripeID } = eventObject;
      if (stripeID) {
        const email = await resolveCustomerEmail(stripeID);
        if (email) {
          const ok = await applyUserPatch(email, {
            'subscription.paymentFailed': true,
            'subscription.paymentFailedAt': Date.now()
          });
          if (ok) logger.warn('Invoice payment failed', { email });
        }
      }
    }

    return c.body(null, 200);
  } catch (e) {
    logger.error('Webhook processing error', { error: e.message });
    return c.body(null, 500);
  }
});

// ==== STATIC ROUTES ====
app.get("/api/health", (c) => c.json({ status: "ok", timestamp: Date.now() }));

/**
 * Parse JSON request body with proper error handling
 *
 * Returns parsed JSON or null if parsing fails. Sets 400 response on failure.
 * Handles SyntaxError from malformed JSON.
 *
 * @async
 * @param {Context} c - Hono context
 * @returns {Promise<Object|null>} Parsed body or null on error
 */
async function parseJsonBody(c) {
  try {
    return await c.req.json();
  } catch (e) {
    if (e instanceof SyntaxError) {
      return null;
    }
    throw e;
  }
}

// ==== AUTH ROUTES ====
app.post("/api/signup", async (c) => {
  try {
    const body = await parseJsonBody(c);
    if (!body) {
      return c.json({ error: 'Invalid request body' }, 400);
    }
    let { email, password, name } = body;

    // Validation
    if (!validateEmail(email)) {
      return c.json({ error: 'Invalid email format or length' }, 400);
    }
    if (!validatePassword(password)) {
      return c.json({ error: 'Password must be 6-72 characters' }, 400);
    }
    if (!validateName(name)) {
      return c.json({ error: 'Name required (max 100 characters)' }, 400);
    }

    email = email.toLowerCase().trim();
    name = escapeHtml(name.trim());

    const hash = await hashPassword(password);
    let insertID = generateUUID()

    try {
      // Insert user first
      await db.insertUser({
        _id: insertID,
        email: email,
        name: name,
        created_at: Date.now()
      });

      // Insert auth record (compensating delete on failure)
      try {
        await db.insertAuth({ email: email, password: hash, userID: insertID });
      } catch (authError) {
        // Rollback: delete the user we just created
        logger.error('Auth insert failed, rolling back user creation', { error: authError.message });
        try {
          await db.executeQuery({ query: 'DELETE FROM Users WHERE _id = ?', params: [insertID] });
        } catch (rollbackError) {
          logger.error('Rollback failed - orphaned user record', { userID: insertID, error: rollbackError.message });
        }
        throw authError;
      }

      const token = await generateToken(insertID);
      setAuthCookies(c, insertID, token);
      logger.info('Signup success');

      return c.json({
        id: insertID.toString(),
        email: email,
        name: name.trim(),
        tokenExpires: tokenExpireTimestamp()
      }, 201);
    } catch (e) {
      if (e.message?.includes('UNIQUE constraint failed') || e.message?.includes('duplicate key') || e.code === 11000) {
        logger.warn('Signup failed - duplicate account');
        return c.json({ error: "Unable to create account with provided credentials" }, 400);
      }
      throw e;
    }
  } catch (e) {
    logger.error('Signup error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/api/signin", async (c) => {
  try {
    const body = await parseJsonBody(c);
    if (!body) {
      return c.json({ error: 'Invalid request body' }, 400);
    }
    let { email, password } = body;

    // Validation
    if (!validateEmail(email)) {
      return c.json({ error: 'Invalid credentials' }, 400);
    }
    if (!password || typeof password !== 'string') {
      return c.json({ error: 'Invalid credentials' }, 400);
    }

    email = email.toLowerCase().trim();
    logger.debug('Attempting signin');

    // Check account lockout
    const lockStatus = isAccountLocked(email);
    if (lockStatus.locked) {
      c.header('Retry-After', String(lockStatus.remainingTime));
      return c.json({
        error: 'Account temporarily locked. Try again later.',
        retryAfter: lockStatus.remainingTime
      }, 429);
    }

    // Check if auth exists
    const auth = await db.findAuth( { email: email });
    if (!auth) {
      logger.debug('Auth record not found');
      recordFailedLogin(email);
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // Verify password
    if (!(await verifyPassword(password, auth.password))) {
      logger.debug('Password verification failed');
      recordFailedLogin(email);
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // Lazy migrate legacy bcrypt hash to scrypt (best-effort, never blocks login)
    if (needsRehash(auth.password)) {
      try {
        const newHash = await hashPassword(password);
        await db.updateAuth({ email }, { password: newHash });
        logger.debug('Password hash migrated to scrypt');
      } catch (e) {
        logger.warn('Password rehash failed', { error: e.message });
      }
    }

    // Get user
    const user = await db.findUser( { email: email });
    if (!user) {
      logger.error('User not found for auth record');
      return c.json({ error: "Invalid credentials" }, 401);
    }

    // Clear failed attempts on successful login
    clearFailedLogins(email);

    // Generate token
    const token = await generateToken(user._id.toString());
    setAuthCookies(c, user._id, token);
    logger.info('Signin success');

    return c.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      ...(user.subscription && {
        subscription: {
          stripeID: user.subscription.stripeID,
          expires: user.subscription.expires,
          status: user.subscription.status,
        },
      }),
      tokenExpires: tokenExpireTimestamp()
    });
  } catch (e) {
    logger.error('Signin error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/api/signout", authMiddleware, async (c) => {
  try {
    const userID = c.get('userID');

    // Clear CSRF token from store
    csrfTokenStore.delete(userID);

    // Clear the HttpOnly cookie
    deleteCookie(c, 'token', {
      httpOnly: true,
      secure: isProd(),
      sameSite: 'Strict',
      path: '/'
    });

    // Clear the CSRF token cookie
    deleteCookie(c, 'csrf_token', {
      httpOnly: false,
      secure: isProd(),
      sameSite: 'Lax',
      path: '/'
    });

    logger.info('Signout success');
    return c.json({ message: "Signed out successfully" });
  } catch (e) {
    logger.error('Signout error', { error: e.message });
    return c.json({ error: "Server error" }, 500);
  }
});

// ==== USER DATA ROUTES ====
app.get("/api/me", authMiddleware, async (c) => {
  const userID = c.get('userID');
  const user = await db.findUser( { _id: userID });
  logger.debug('/me checking for user');
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json(user);
});

app.put("/api/me", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { name } = body;

    // Validation
    if (name !== undefined && !validateName(name)) {
      return c.json({ error: 'Name must be 1-100 characters' }, 400);
    }

    // Whitelist of fields users are allowed to update
    const UPDATEABLE_USER_FIELDS = ['name'];

    // Find user first to verify existence
    const user = await db.findUser( { _id: userID });
    if (!user) return c.json({ error: "User not found" }, 404);

    // Whitelist approach - only allow specific fields
    const update = {};
    for (const [key, value] of Object.entries(body)) {
      if (UPDATEABLE_USER_FIELDS.includes(key)) {
        // Sanitize string values to prevent XSS
        update[key] = typeof value === 'string' ? escapeHtml(value.trim()) : value;
      }
    }

    if (Object.keys(update).length === 0) {
      return c.json({ error: "No valid fields to update" }, 400);
    }

    // Update user document
    const result = await db.updateUser( { _id: userID }, { $set: update });

    if (result.modifiedCount === 0) {
      return c.json({ error: "No changes made" }, 400);
    }

    // Return updated user
    const updatedUser = await db.findUser( { _id: userID });
    return c.json(updatedUser);
  } catch (err) {
    logger.error('Update user error', { error: err.message });
    return c.json({ error: "Failed to update user" }, 500);
  }
});

// ==== USAGE TRACKING ====
app.post("/api/usage", authMiddleware, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { operation } = body; // "check" or "track"

    if (!operation || !['check', 'track'].includes(operation)) {
      return c.json({ error: "Invalid operation. Must be 'check' or 'track'" }, 400);
    }

    // Get user
    const user = await db.findUser( { _id: userID });
    if (!user) return c.json({ error: "User not found" }, 404);

    // Check if user is a subscriber - subscribers get unlimited
    const isSubscriber = user.subscription?.status === 'active' &&
      (!user.subscription?.expires || user.subscription.expires > Math.floor(Date.now() / 1000));

    if (isSubscriber) {
      return c.json({
        remaining: -1,
        total: -1,
        isSubscriber: true,
        subscription: {
          status: user.subscription.status,
          expiresAt: user.subscription.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
        }
      });
    }

    // Get usage limit from environment
    const limit = parseInt(process.env.FREE_USAGE_LIMIT || '20');
    const now = Math.floor(Date.now() / 1000);

    // Initialize usage if not set
    let usage = user.usage || { count: 0, reset_at: null };

    // Check if we need to reset (30 days = 2592000 seconds)
    if (!usage.reset_at || now > usage.reset_at) {
      const newResetAt = now + (30 * 24 * 60 * 60); // 30 days from now
      // Reset usage - atomic set operation
      await db.updateUser(
        { _id: userID },
        { $set: { usage: { count: 0, reset_at: newResetAt } } }
      );
      usage = { count: 0, reset_at: newResetAt };
    }

    if (operation === 'track') {
      // Atomic increment first to prevent race conditions
      // Then verify we haven't exceeded the limit
      await db.updateUser(
        { _id: userID },
        { $inc: { 'usage.count': 1 } }
      );

      // Re-read user to get actual count after atomic increment
      const updatedUser = await db.findUser( { _id: userID });
      const actualCount = updatedUser?.usage?.count || 1;

      // If we exceeded the limit, rollback the increment and return 429
      if (actualCount > limit) {
        await db.updateUser(
          { _id: userID },
          { $inc: { 'usage.count': -1 } }
        );
        return c.json({
          error: "Usage limit reached",
          remaining: 0,
          total: limit,
          isSubscriber: false
        }, 429);
      }

      usage.count = actualCount;
    }

    // Return usage info (with subscription details for free users too)
    return c.json({
      remaining: Math.max(0, limit - usage.count),
      total: limit,
      isSubscriber: false,
      used: usage.count,
      subscription: user.subscription ? {
        status: user.subscription.status,
        expiresAt: user.subscription.expires ? new Date(user.subscription.expires * 1000).toISOString() : null
      } : null
    });

  } catch (error) {
    logger.error('Usage tracking error', { error: error.message });
    return c.json({ error: "Server error" }, 500);
  }
});

// ==== PAYMENT ROUTES ====
app.post("/api/checkout", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { email, lookup_key } = body;

    if (!email || !lookup_key) return c.json({ error: "Missing email or lookup_key" }, 400);

    // Verify the email matches the authenticated user
    const user = await db.findUser( { _id: userID });
    if (!user || user.email !== email) return c.json({ error: "Email mismatch" }, 403);

    const prices = await stripe.prices.list({ lookup_keys: [lookup_key], expand: ["data.product"] });

    if (!prices.data || prices.data.length === 0) {
      return c.json({ error: `No price found for lookup_key: ${lookup_key}` }, 400);
    }

    // Use FRONTEND_URL env var or origin header, fallback to localhost for dev
    const origin = process.env.FRONTEND_URL || c.req.header('origin') || `http://localhost:${port}`;

    const session = await stripe.checkout.sessions.create({
      customer_email: email,
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: prices.data[0].id, quantity: 1 }],
      billing_address_collection: "auto",
      success_url: `${origin}/app/payment?success=true`,
      cancel_url: `${origin}/app/payment?canceled=true`,
      subscription_data: { metadata: { email } },
    });
    return c.json({ url: session.url, id: session.id, customerID: session.customer });
  } catch (e) {
    logger.error('Checkout session error', { error: e.message });
    return c.json({ error: "Stripe session failed" }, 500);
  }
});

app.post("/api/portal", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();
    const { customerID } = body;

    if (!customerID) return c.json({ error: "Missing customerID" }, 400);

    // Verify the customerID matches the authenticated user's subscription
    const user = await db.findUser( { _id: userID });
    if (!user || (user.subscription?.stripeID && user.subscription.stripeID !== customerID)) {
      return c.json({ error: "Unauthorized customerID" }, 403);
    }

    // Use FRONTEND_URL env var or origin header, fallback to localhost for dev
    const origin = process.env.FRONTEND_URL || c.req.header('origin') || `http://localhost:${port}`;
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: `${origin}/app/payment?portal=return`,
    });
    return c.json({ url: portalSession.url, id: portalSession.id });
  } catch (e) {
    logger.error('Portal session error', { error: e.message });
    return c.json({ error: "Stripe portal failed" }, 500);
  }
});

// ==== X PROFILE / QR ROUTES ====

// View recent profile lookups (admin — protected by ADMIN_SECRET env var)
app.get("/lookups", async (c) => {
  const secret = process.env.ADMIN_SECRET;
  if (!secret || c.req.query("key") !== secret) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  const limit = Math.min(parseInt(c.req.query("limit") || "100"), 1000);
  const lookups = await databaseManager.getProfileLookups(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, limit
  );
  return c.json({ count: lookups.length, lookups });
});

// Clear all caches: disk images + SQLite profiles + persistent browser (admin)
app.get("/clear-cache", async (c) => {
  const secret = process.env.ADMIN_SECRET;
  if (!secret || c.req.query("key") !== secret) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  try {
    const files = readdirSync(IMAGE_CACHE_DIR);
    for (const file of files) {
      unlinkSync(resolve(IMAGE_CACHE_DIR, file));
    }
    const profiles = await databaseManager.clearAllProfiles(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString
    );
    if (persistentBrowser) {
      await persistentBrowser.close();
      persistentBrowser = null;
      logger.info('Closed persistent browser to clear cache');
    }
    logger.info('Caches cleared', { images: files.length, profiles });
    return c.json({ images: files.length, profiles, browser: 'reset' });
  } catch (err) {
    return c.json({ error: err.message }, 500);
  }
});

// Serve a disk-cached profile image (avatar/banner) by id
app.get("/images/:id", async (c) => {
  try {
    const id = c.req.param("id");
    if (!id || !/^[a-zA-Z0-9_]+$/.test(id)) {
      return c.json({ error: "Invalid image id" }, 400);
    }

    let filePath = resolve(IMAGE_CACHE_DIR, `${id}.jpg`);
    let contentType = 'image/jpeg';
    if (!existsSync(filePath)) {
      filePath = resolve(IMAGE_CACHE_DIR, `${id}.png`);
      contentType = 'image/png';
    }
    if (!existsSync(filePath)) {
      return c.json({ error: "Image not found" }, 404);
    }

    const buffer = readFileSync(filePath);
    return c.body(buffer, 200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store'
    });
  } catch (error) {
    logger.error('Image serve error', { error: error.message });
    return c.json({ error: "Failed to serve image" }, 500);
  }
});

// Fetch an X profile (7-day SQLite cache; X API + image caching on miss)
app.get("/user/:username", async (c) => {
  try {
    if (!xClient) {
      return c.json({ error: "X API service unavailable" }, 503);
    }

    const username = c.req.param("username");
    if (!username || typeof username !== 'string') {
      return c.json({ error: "Invalid username" }, 400);
    }

    const cleanUsername = username.replace(/^@/, '').trim().toLowerCase();
    if (!/^[a-zA-Z0-9_]{1,15}$/.test(cleanUsername)) {
      return c.json({ error: "Invalid username format" }, 400);
    }

    // Log the lookup (fire and forget — don't block the response)
    databaseManager.logProfileLookup(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      cleanUsername, getClientIP(c), 'api'
    ).catch(() => {});

    // Check SQLite cache first (no rate limit for cached responses)
    const forceRefresh = c.req.query('refresh') === '1';
    const cached = await databaseManager.getCachedProfile(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, cleanUsername
    );
    if (!forceRefresh && cached && Date.now() - cached.cached_at < PROFILE_CACHE_TTL) {
      return c.json(cached.data);
    }

    // Rate limit only applies to actual X API calls (cache misses); 3/day per IP
    if (process.env.DISABLE_RATE_LIMIT !== 'true') {
      const ip = getClientIP(c);
      const now = Date.now();
      const windowMs = 24 * 60 * 60 * 1000;
      const maxRequests = 3;

      const prior = (xApiRateLimitStore.get(ip) || []).filter(time => time > now - windowMs);
      if (prior.length >= maxRequests) {
        logger.warn('X API daily limit exceeded', { ip });
        return c.json({
          error: 'Daily limit reached. Try again tomorrow or use a previously searched profile.',
          retryAfter: Math.ceil((prior[0] + windowMs - now) / 1000)
        }, 429);
      }
      prior.push(now);
      xApiRateLimitStore.set(ip, prior);
    }

    const response = await xClient.users.getByUsername(cleanUsername, {
      "user.fields": [
        "profile_image_url", "profile_banner_url", "name", "description",
        "verified", "verified_type", "location", "url", "created_at",
        "public_metrics", "entities"
      ]
    });

    if (!response.data) {
      return c.json({ error: "User not found" }, 404);
    }

    const user = response.data;
    const urlEntity = user.entities?.url?.urls?.[0];
    const displayUrl = urlEntity?.display_url || urlEntity?.displayUrl || null;
    const expandedUrl = urlEntity?.expanded_url || urlEntity?.expandedUrl || user.url;

    let description = user.description || '';
    const descriptionUrls = user.entities?.description?.urls || [];
    for (const urlInfo of descriptionUrls) {
      const shortUrl = urlInfo.url;
      const display = urlInfo.display_url || urlInfo.displayUrl;
      if (shortUrl && display) {
        description = description.replace(shortUrl, display);
      }
    }

    // Cache avatar and banner images locally
    const avatarId = `${cleanUsername}_avatar`;
    const bannerId = `${cleanUsername}_banner`;

    // XDK returns camelCase (profileImageUrl); handle both formats
    const profileImageUrl = user.profileImageUrl || user.profile_image_url;
    const profileBannerUrl = user.profileBannerUrl || user.profile_banner_url;

    // Get higher-res avatar (remove _normal suffix)
    const hiResAvatar = profileImageUrl?.replace('_normal', '_400x400');

    await Promise.all([
      cacheImage(hiResAvatar, avatarId),
      cacheImage(profileBannerUrl, bannerId)
    ]);

    const metrics = user.publicMetrics || user.public_metrics || {};

    const userData = {
      id: user.id,
      username: user.username,
      name: user.name,
      profile_image_url: profileImageUrl ? `/images/${avatarId}` : null,
      profile_banner_url: profileBannerUrl ? `/images/${bannerId}` : null,
      description,
      verified: user.verified,
      verified_type: user.verifiedType || user.verified_type,
      location: user.location,
      url: expandedUrl,
      display_url: displayUrl,
      created_at: user.createdAt || user.created_at,
      followers_count: metrics.followersCount || metrics.followers_count,
      following_count: metrics.followingCount || metrics.following_count,
      tweet_count: metrics.tweetCount || metrics.tweet_count
    };

    await databaseManager.setCachedProfile(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      cleanUsername, userData
    );

    return c.json(userData);
  } catch (error) {
    logger.error('X API error', { username: c.req.param("username"), error: error.message, status: error.status });
    if (error.status === 404) {
      return c.json({ error: "User not found" }, 404);
    }
    return c.json({ error: "Failed to fetch user data" }, 500);
  }
});

// Generate a QR wallpaper screenshot via Playwright WebKit (cached profiles only)
app.get("/qr/:username/image", async (c) => {
  const username = c.req.param("username");
  const rawW = c.req.query("w");
  const rawH = c.req.query("h");
  const rawScale = c.req.query("scale");

  const width = parseInt(rawW || "393");
  const height = parseInt(rawH || "852");
  const scale = parseFloat(rawScale || "3");
  const theme = c.req.query("theme") === "light" ? "light" : "dark";

  // Validate dimensions (max 1200x1000 base, up to 3600x3000 at scale 3)
  if (isNaN(width) || isNaN(height) || isNaN(scale) || width < 100 || width > 1200 || height < 100 || height > 1000 || scale < 1 || scale > 4) {
    return c.json({ error: "Invalid dimensions" }, 400);
  }

  const cleanUsername = username.replace(/^@/, '').trim().toLowerCase();
  if (!/^[a-zA-Z0-9_]{1,15}$/.test(cleanUsername)) {
    return c.json({ error: "Invalid username format" }, 400);
  }

  // Only allow screenshots for cached profiles (prevents X API calls)
  const profileCached = await databaseManager.getCachedProfile(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, cleanUsername
  );
  if (!profileCached) {
    return c.json({ error: "Profile not cached. View the profile first." }, 404);
  }

  const cacheKey = `${cleanUsername}_${width}x${height}_${scale}_${theme}`;

  const cachedScreenshot = await databaseManager.getCachedImage(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, cacheKey
  );
  if (cachedScreenshot && Date.now() - cachedScreenshot.cached_at < SCREENSHOT_CACHE_TTL) {
    return c.body(cachedScreenshot.image, 200, {
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${cleanUsername}-qr.png"`,
      'Cache-Control': 'no-store'
    });
  }

  const browser = await getBrowser();
  if (!browser) {
    logger.error('Browser unavailable for screenshot', { username: cleanUsername });
    return c.json({ error: "Screenshot service unavailable" }, 503);
  }

  let context = null;
  try {
    // Only navigate to localhost (security: never hit external sites)
    const baseUrl = !isProd() ? 'http://localhost:5173' : `http://localhost:${port}`;
    const targetUrl = `${baseUrl}/app/home?u=${cleanUsername}&screenshot=1&t=${Date.now()}`;

    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.hostname !== 'localhost') {
      logger.error('Blocked non-localhost screenshot target', { targetUrl });
      return c.json({ error: "Invalid target" }, 400);
    }

    context = await browser.newContext({
      viewport: { width, height },
      deviceScaleFactor: scale,
      colorScheme: theme,
    });
    await context.route('**/*', route => route.continue());
    await context.addInitScript(() => {
      if (window.caches) window.caches.keys().then(keys => keys.forEach(k => caches.delete(k)));
    });
    const page = await context.newPage();

    await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 30000 });

    // Wait for profile content to render (canvas = QR code is ready)
    try {
      await page.waitForSelector('canvas', { timeout: 10000 });
      await page.evaluate(() => document.fonts.ready);
      await new Promise(r => setTimeout(r, 500));
    } catch {
      logger.debug('Canvas not found, taking screenshot anyway');
    }

    const screenshot = await page.screenshot({ type: 'png' });
    await context.close();
    context = null;
    screenshotCount++;

    await databaseManager.setCachedImage(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      cacheKey, screenshot
    );

    return c.body(screenshot, 200, {
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${cleanUsername}-qr.png"`,
      'Cache-Control': 'no-store'
    });
  } catch (error) {
    logger.error('Screenshot failed', { username: cleanUsername, error: error.message });
    if (context) await context.close();
    return c.json({ error: "Failed to generate image" }, 500);
  }
});

// ==== STATIC FILE SERVING (Production) ====
const staticDir = resolve(__dirname, config.staticDir);

// Serve static files
app.use('/*', serveStatic({ root: staticDir }));

// Dynamic OG/Twitter tags for shared profile links (after static, before SPA fallback)
app.get('/:username', async (c) => {
  const username = c.req.param('username');
  const indexPath = resolve(staticDir, 'index.html');
  let html;
  try {
    html = readFileSync(indexPath, 'utf8');
  } catch {
    return c.text('Not found', 404);
  }

  if (!/^[a-zA-Z0-9_]{1,15}$/.test(username)) {
    return c.html(html);
  }

  const cached = await databaseManager.getCachedProfile(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
    username.toLowerCase()
  );

  if (cached?.data) {
    const d = cached.data;
    const title = escapeHtml(`${d.name} (@${d.username})`);
    const desc = escapeHtml(d.description || `View ${d.name}'s X profile wallpaper`);
    const img = escapeHtml(d.profile_image_url ? `${c.req.url.split('/' + username)[0]}${d.profile_image_url}` : '/icons/icon.png');
    const url = escapeHtml(c.req.url);

    html = html
      .replace(/<meta property="og:title" content="[^"]*">/, `<meta property="og:title" content="${title}">`)
      .replace(/<meta property="og:description" content="[^"]*">/, `<meta property="og:description" content="${desc}">`)
      .replace(/<meta property="og:image" content="[^"]*">/, `<meta property="og:image" content="${img}">`)
      .replace(/<meta property="og:url" content="[^"]*">/, `<meta property="og:url" content="${url}">`)
      .replace(/<meta name="twitter:title" content="[^"]*">/, `<meta name="twitter:title" content="${title}">`)
      .replace(/<meta name="twitter:description" content="[^"]*">/, `<meta name="twitter:description" content="${desc}">`)
      .replace(/<meta name="twitter:image" content="[^"]*">/, `<meta name="twitter:image" content="${img}">`);
  }

  return c.html(html);
});

// SPA fallback — only for non-asset routes
app.get('*', async (c) => {
  if (c.req.path.startsWith('/api/') || c.req.path.match(/\.\w+$/)) {
    return c.notFound();
  }
  try {
    const indexPath = resolve(staticDir, 'index.html');
    const file = await promisify(readFile)(indexPath);
    return c.html(new TextDecoder().decode(file));
  } catch {
    return c.text("Welcome to Skateboard API", 200);
  }
});

// ==== ERROR HANDLER ====
app.onError((err, c) => {
  const requestId = Math.random().toString(36).substr(2, 9);

  logger.error('Unhandled error occurred', {
    message: err.message,
    stack: !isProd() ? err.stack : undefined,
    path: c.req.path,
    method: c.req.method,
    requestId
  });

  return c.json({
    error: !isProd() ? err.message : 'Internal server error',
    ...(!isProd() && { stack: err.stack })
  }, 500);
});

// ==== UTILITY FUNCTIONS ====

/**
 * Check if the server is running in production mode
 *
 * Reads the NODE_ENV environment variable. Returns true only when
 * NODE_ENV is explicitly set to "production".
 *
 * @returns {boolean} True if NODE_ENV === "production"
 */
function isProd() {
  return process.env.NODE_ENV === 'production';
}

/**
 * Load environment variables from .env and optional .env.local file.
 *
 * Reads in two passes: backend/.env first (may be symlink to shared creds),
 * then backend/.env.local for project-specific overrides (wins on conflict).
 * Creates .env from .env.example if it doesn't exist. Only called in
 * non-production mode — Railway injects vars directly in prod.
 *
 * @returns {void}
 */
function loadLocalENV() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const envFilePath = resolve(__dirname, './.env');
  const envLocalPath = resolve(__dirname, './.env.local');
  const envExamplePath = resolve(__dirname, './.env.example');

  // Check if .env exists, if not create it from .env.example
  try {
    statSync(envFilePath);
  } catch (err) {
    try {
      const exampleData = readFileSync(envExamplePath, 'utf8');
      writeFileSync(envFilePath, exampleData);
    } catch (exampleErr) {
      logger.error('Failed to create .env from template', { error: exampleErr.message });
      return;
    }
  }

  // Load .env (may be symlink to shared creds)
  loadEnvFile(envFilePath);

  // Load .env.local overrides (project-specific, optional)
  loadEnvFile(envLocalPath);
}

/**
 * Parse a .env file and apply key=value pairs to process.env.
 * Skips blank lines and comments. Handles quoted values and values containing '='.
 * Silently skips if file doesn't exist.
 * @param {string} filePath - Absolute path to the .env file
 * @returns {void}
 */
function loadEnvFile(filePath) {
  try {
    const data = readFileSync(filePath, 'utf8');
    for (let line of data.split(/\r?\n/)) {
      if (!line || line.trim().startsWith('#')) continue;
      let [key, ...valueParts] = line.split('=');
      let value = valueParts.join('=');
      if (key && value) {
        key = key.trim();
        value = value.trim().replace(/^["']|["']$/g, '');
        process.env[key] = value;
      }
    }
  } catch {
    // File doesn't exist or unreadable — silent
  }
}

// ==== SERVER STARTUP ====
const server = serve({
  fetch: app.fetch,
  port,
  hostname: '::'  // Listen on both IPv4 and IPv6
}, (info) => {
  logger.info('Server started successfully', {
    port: info.port,
    environment: !isProd() ? 'development' : 'production'
  });
});

// Handle graceful shutdown on SIGTERM and SIGINT - NEED THIS FOR PROXY
if (typeof process !== 'undefined') {
  const gracefulShutdown = async (signal) => {
    console.log(`${signal} received. Shutting down gracefully...`);

    // Close HTTP server first
    server.close(async () => {
      console.log('Server closed');

      // Close all database connections with error handling
      try {
        await databaseManager.closeAll();
        console.log('Database connections closed');
      } catch (err) {
        console.error('Error closing database connections:', err);
      }

      process.exit(0);
    });

    // Force exit after 10 seconds if graceful shutdown hangs
    setTimeout(() => {
      console.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}
