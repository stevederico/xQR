// ==== IMPORTS ====
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { cors } from "hono/cors";
import { compress } from "hono/compress";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { Client } from "@xdevplatform/xdk";

// Playwright loaded lazily on first screenshot request
let playwright = null;
let persistentBrowser = null;
let screenshotCount = 0;
const MAX_SCREENSHOTS_BEFORE_RESTART = 100;

async function getPlaywright() {
  if (playwright) return playwright;
  try {
    playwright = await import("playwright");
    console.log('✅ Playwright loaded (lazy)');
    return playwright;
  } catch (e) {
    console.log('⚠️  Playwright not available - screenshot feature disabled');
    return null;
  }
}

async function restartBrowser() {
  if (persistentBrowser) {
    console.log('[BROWSER] Restarting to free memory...');
    try {
      await persistentBrowser.close();
    } catch (e) {
      // Ignore close errors
    }
    persistentBrowser = null;
  }
  screenshotCount = 0;
}

async function getBrowser() {
  const pw = await getPlaywright();
  if (!pw) return null;

  // Restart browser if screenshot count exceeded (memory management)
  if (screenshotCount >= MAX_SCREENSHOTS_BEFORE_RESTART && persistentBrowser) {
    await restartBrowser();
  }

  // Reuse existing browser if healthy
  if (persistentBrowser?.isConnected()) {
    return persistentBrowser;
  }

  // Launch new browser
  console.log('[BROWSER] Launching persistent WebKit instance');
  persistentBrowser = await pw.webkit.launch({ headless: true });
  return persistentBrowser;
}

import { databaseManager } from "./adapters/manager.js";
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, readFileSync, writeFileSync, statSync, mkdirSync, existsSync, unlinkSync, readdirSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';

// ==== LRU MAP (capped size with eviction) ====
class LRUMap extends Map {
  constructor(maxSize) {
    super();
    this.maxSize = maxSize;
  }
  set(key, value) {
    if (this.has(key)) this.delete(key);
    super.set(key, value);
    if (this.size > this.maxSize) {
      const firstKey = this.keys().next().value;
      this.delete(firstKey);
    }
    return this;
  }
  get(key) {
    if (!this.has(key)) return undefined;
    const value = super.get(key);
    this.delete(key);
    super.set(key, value);
    return value;
  }
}

// ==== RATE LIMITING ====
const rateLimitStore = new LRUMap(10000);

// ==== X API CACHE ====
const PROFILE_CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 1 week
const SCREENSHOT_CACHE_TTL = 60 * 60 * 1000; // 1 hour

// ==== CSRF PROTECTION ====
const csrfTokenStore = new LRUMap(5000);
const CSRF_TOKEN_EXPIRY = 24 * 60 * 60 * 1000;

function generateCSRFToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Rate limiter middleware for Hono
const rateLimiter = (maxRequests, windowMs, routeName = 'unknown') => {
  return async (c, next) => {
    const key = c.req.header('x-forwarded-for') || 'unknown';
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!rateLimitStore.has(key)) {
      rateLimitStore.set(key, []);
    }

    const requests = rateLimitStore.get(key);
    const validRequests = requests.filter(time => time > windowStart);

    if (validRequests.length >= maxRequests) {
      console.error(`[${new Date().toISOString()}] RATE LIMIT EXCEEDED: IP ${key} blocked on ${routeName}`);
      return c.json({
        error: 'Too many requests, please try again later.',
        retryAfter: Math.ceil((windowStart + windowMs - now) / 1000)
      }, 429);
    }

    validRequests.push(now);
    rateLimitStore.set(key, validRequests);
    await next();
  };
};

const authLimiter = rateLimiter(10, 15 * 60 * 1000, 'auth routes');
const globalLimiter = rateLimiter(300, 15 * 60 * 1000, 'global');

// Cleanup intervals
setInterval(() => {
  const now = Date.now();
  const maxWindow = 15 * 60 * 1000;
  for (const [ip, requests] of rateLimitStore.entries()) {
    const validRequests = requests.filter(time => time > now - maxWindow);
    if (validRequests.length === 0) {
      rateLimitStore.delete(ip);
    } else {
      rateLimitStore.set(ip, validRequests);
    }
  }
}, 60 * 60 * 1000);

setInterval(() => {
  const now = Date.now();
  for (const [userID, data] of csrfTokenStore.entries()) {
    if (now - data.timestamp > CSRF_TOKEN_EXPIRY) {
      csrfTokenStore.delete(userID);
    }
  }
}, 60 * 60 * 1000);

// Clean up expired caches (runs daily)
setInterval(async () => {
  try {
    // Clean expired profile cache
    const deletedProfiles = await databaseManager.cleanExpiredProfiles(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      PROFILE_CACHE_TTL
    );
    if (deletedProfiles > 0) {
      console.log(`[CACHE CLEANUP] Removed ${deletedProfiles} expired profiles`);
    }

    // Clean expired screenshot cache
    const deletedImages = await databaseManager.cleanExpiredImages(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      SCREENSHOT_CACHE_TTL
    );
    if (deletedImages > 0) {
      console.log(`[CACHE CLEANUP] Removed ${deletedImages} expired screenshots`);
    }

    // Clean expired disk cache (avatar/banner images)
    cleanExpiredDiskCache();
  } catch (err) {
    console.error('[CACHE CLEANUP] Error:', err.message);
  }
}, 24 * 60 * 60 * 1000);

// ==== CONFIG & ENV ====
if (!isProd()) {
  loadLocalENV();
}

function resolveEnvironmentVariables(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/\$\{([^}]+)\}/g, (match, varName) => {
    const envValue = process.env[varName];
    return envValue !== undefined ? envValue : match;
  });
}

let config;
try {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const configPath = resolve(__dirname, './config.json');
  const configData = await promisify(readFile)(configPath);
  const rawConfig = JSON.parse(configData.toString());

  config = {
    client: rawConfig.client,
    database: {
      ...rawConfig.database,
      connectionString: resolveEnvironmentVariables(rawConfig.database.connectionString)
    }
  };
} catch (err) {
  console.error('Failed to load config:', err);
  config = {
    client: "http://localhost:5173",
    database: {
      db: "MyApp",
      dbType: "sqlite",
      connectionString: "./databases/MyApp.db"
    }
  };
}

const JWT_SECRET = process.env.JWT_SECRET;
const X_BEARER_TOKEN = process.env.X_BEARER_TOKEN;

if (!JWT_SECRET) {
  console.warn('⚠️  JWT_SECRET not set - authentication disabled');
}

console.log('✅ Backend initialized');

const isDevelopment = process.env.NODE_ENV !== 'production';

// ==== DATABASE CONFIG ====
const currentDbConfig = config.database;

// ==== X API CLIENT ====
let xClient = null;
if (X_BEARER_TOKEN) {
  xClient = new Client({ bearerToken: X_BEARER_TOKEN });
} else {
  console.warn('⚠️  X_BEARER_TOKEN not set - X API functionality disabled');
}

// ==== HONO SETUP ====
const app = new Hono();
const allowedOrigin = config.client;

// CORS middleware
app.use('*', cors({
  origin: allowedOrigin,
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
}));

// Response compression (gzip/deflate)
app.use('*', compress());

// Security headers
app.use('*', async (c, next) => {
  await next();
  c.header('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
  );
  if (!isDevelopment) {
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  c.header('X-Frame-Options', 'DENY');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
});

// Request logging
app.use('*', async (c, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  const timestamp = new Date().toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
  console.log(`[${timestamp}] "${c.req.method} ${c.req.path}" ${c.res.status} ${ms}ms`);
});

// Global rate limiting
app.use('*', globalLimiter);

const tokenExpirationDays = 30;

// ==== BCRYPT HELPERS ====
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ==== JWT HELPERS ====
function tokenExpireTimestamp() {
  return Math.floor(Date.now() / 1000) + tokenExpirationDays * 24 * 60 * 60;
}

async function generateToken(userID) {
  if (!JWT_SECRET) throw new Error("JWT_SECRET not configured");
  const exp = tokenExpireTimestamp();
  return jwt.sign({ userID, exp }, JWT_SECRET, { algorithm: 'HS256' });
}

// Auth middleware for Hono
async function authMiddleware(c, next) {
  if (!JWT_SECRET) {
    return c.json({ error: "Authentication service unavailable" }, 503);
  }

  const token = getCookie(c, 'token');
  if (!token) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
    c.set('userID', payload.userID);
    await next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return c.json({ error: "Token expired" }, 401);
    }
    return c.json({ error: "Invalid token" }, 401);
  }
}

// CSRF middleware for Hono
async function csrfProtection(c, next) {
  const csrfToken = c.req.header('x-csrf-token');
  const userID = c.get('userID');

  if (!csrfToken || !userID) {
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  const storedData = csrfTokenStore.get(userID);
  if (!storedData || storedData.token !== csrfToken) {
    return c.json({ error: 'Invalid CSRF token' }, 403);
  }

  if (Date.now() - storedData.timestamp > CSRF_TOKEN_EXPIRY) {
    csrfTokenStore.delete(userID);
    return c.json({ error: 'CSRF token expired' }, 403);
  }

  await next();
}

// ==== VALIDATION ====
const escapeHtml = (text) => {
  if (typeof text !== 'string') return text;
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '/': '&#x2F;' };
  return text.replace(/[&<>"'/]/g, (char) => map[char]);
};

const validateEmail = (email) => {
  if (!email || typeof email !== 'string' || email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

const validatePassword = (password) => {
  return password && typeof password === 'string' && password.length >= 6 && password.length <= 72;
};

const validateName = (name) => {
  return name && typeof name === 'string' && name.trim().length > 0 && name.length <= 100;
};

function generateUUID() {
  return crypto.randomUUID();
}

// ==== DISK IMAGE CACHE ====
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const IMAGE_CACHE_DIR = resolve(__dirname, './cache');

// Ensure cache directory exists
if (!existsSync(IMAGE_CACHE_DIR)) {
  mkdirSync(IMAGE_CACHE_DIR, { recursive: true });
}

// Clean expired files from disk cache (7 days TTL)
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
      } catch (e) {
        // Ignore stat/unlink errors
      }
    }
    if (deleted > 0) {
      console.log(`[CACHE CLEANUP] Removed ${deleted} expired disk images`);
    }
  } catch (err) {
    console.error('[CACHE CLEANUP] Disk cache error:', err.message);
  }
}

// Helper to download and cache an image to disk (async to avoid blocking)
async function cacheImage(imageUrl, cacheId) {
  if (!imageUrl) return null;
  try {
    const response = await fetch(imageUrl);
    if (!response.ok) return null;
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    const ext = contentType.includes('png') ? 'png' : 'jpg';
    const buffer = Buffer.from(await response.arrayBuffer());
    const filePath = resolve(IMAGE_CACHE_DIR, `${cacheId}.${ext}`);
    await writeFile(filePath, buffer);
    return cacheId;
  } catch (err) {
    console.error(`Failed to cache image ${cacheId}:`, err.message);
    return null;
  }
}

// ==== ROUTES ====

// Health check
app.get("/health", (c) => c.json({ status: "ok", timestamp: Date.now() }));

// Clear all caches (images + profiles + browser)
app.get("/clear-cache", async (c) => {
  try {
    // Clear image files
    const files = readdirSync(IMAGE_CACHE_DIR);
    for (const file of files) {
      unlinkSync(resolve(IMAGE_CACHE_DIR, file));
    }
    // Clear SQLite profile cache
    const profiles = await databaseManager.clearAllProfiles(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString
    );
    // Close persistent browser to clear its cache
    if (persistentBrowser) {
      await persistentBrowser.close();
      persistentBrowser = null;
      console.log('[BROWSER] Closed persistent browser to clear cache');
    }
    console.log(`[CACHE] Cleared ${files.length} images, ${profiles} profiles, browser reset`);
    return c.json({ images: files.length, profiles, browser: 'reset' });
  } catch (err) {
    return c.json({ error: err.message }, 500);
  }
});

// Serve cached profile images from disk
app.get("/images/:id", async (c) => {
  try {
    const id = c.req.param("id");
    if (!id || !/^[a-zA-Z0-9_]+$/.test(id)) {
      return c.json({ error: "Invalid image id" }, 400);
    }

    // Check for jpg or png
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
    console.error("Image serve error:", error.message);
    return c.json({ error: "Failed to serve image" }, 500);
  }
});

// X API route
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

    // Check SQLite cache first (no rate limit for cached responses)
    const cached = await databaseManager.getCachedProfile(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      cleanUsername
    );
    if (cached && Date.now() - cached.cached_at < PROFILE_CACHE_TTL) {
      console.log(`[CACHE HIT] ${cleanUsername} (cached ${Math.round((Date.now() - cached.cached_at) / 3600000)}h ago)`);
      return c.json(cached.data);
    }

    // Rate limit only applies to actual X API calls (cache misses)
    // Set DISABLE_RATE_LIMIT=true to disable
    if (process.env.DISABLE_RATE_LIMIT !== 'true') {
      const ip = c.req.header('x-forwarded-for') || 'unknown';
      const now = Date.now();
      const windowMs = 24 * 60 * 60 * 1000; // 24 hours
      const maxRequests = 3;

      if (!rateLimitStore.has(ip)) {
        rateLimitStore.set(ip, []);
      }
      const requests = rateLimitStore.get(ip).filter(time => time > now - windowMs);
      if (requests.length >= maxRequests) {
        console.error(`[RATE LIMIT] IP ${ip} exceeded 3/day X API limit`);
        return c.json({
          error: 'Daily limit reached. Try again tomorrow or use a previously searched profile.',
          retryAfter: Math.ceil((requests[0] + windowMs - now) / 1000)
        }, 429);
      }
      requests.push(now);
      rateLimitStore.set(ip, requests);
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
    console.log("X API response for", cleanUsername, ":", JSON.stringify(user, null, 2));

    const urlEntity = user.entities?.url?.urls?.[0];
    const displayUrl = urlEntity?.display_url || null;
    const expandedUrl = urlEntity?.expanded_url || user.url;

    let description = user.description || '';
    const descriptionUrls = user.entities?.description?.urls || [];
    for (const urlInfo of descriptionUrls) {
      if (urlInfo.url && urlInfo.display_url) {
        description = description.replace(urlInfo.url, urlInfo.display_url);
      }
    }

    // Cache avatar and banner images locally
    const avatarId = `${cleanUsername}_avatar`;
    const bannerId = `${cleanUsername}_banner`;

    // Get higher res avatar (remove _normal suffix)
    const hiResAvatar = user.profile_image_url?.replace('_normal', '_400x400');

    // Download images in parallel
    await Promise.all([
      cacheImage(hiResAvatar, avatarId),
      cacheImage(user.profile_banner_url, bannerId)
    ]);

    const userData = {
      id: user.id,
      username: user.username,
      name: user.name,
      profile_image_url: user.profile_image_url ? `/images/${avatarId}` : null,
      profile_banner_url: user.profile_banner_url ? `/images/${bannerId}` : null,
      description,
      verified: user.verified,
      verified_type: user.verified_type,
      location: user.location,
      url: expandedUrl,
      display_url: displayUrl,
      created_at: user.created_at,
      followers_count: user.public_metrics?.followers_count,
      following_count: user.public_metrics?.following_count,
      tweet_count: user.public_metrics?.tweet_count
    };

    // Cache the response in SQLite
    await databaseManager.setCachedProfile(
      currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
      cleanUsername, userData
    );
    console.log(`[CACHE MISS] ${cleanUsername} - fetched from X API, cached for 7 days`);

    return c.json(userData);
  } catch (error) {
    console.error("X API error:", error.message);
    if (error.status === 404) {
      return c.json({ error: "User not found" }, 404);
    }
    return c.json({ error: "Failed to fetch user data" }, 500);
  }
});

// Screenshot generation endpoint using Playwright WebKit (Safari-accurate rendering)
app.get("/qr/:username/image", async (c) => {
  const username = c.req.param("username");
  const rawW = c.req.query("w");
  const rawH = c.req.query("h");
  const rawScale = c.req.query("scale");

  const width = parseInt(rawW || "393");
  const height = parseInt(rawH || "852");
  const scale = parseFloat(rawScale || "3");
  const theme = c.req.query("theme") === "light" ? "light" : "dark";

  console.log(`[SCREENSHOT] Params: w=${rawW}(${width}) h=${rawH}(${height}) scale=${rawScale}(${scale})`);

  // Validate dimensions (max 1200x1000 base, produces up to 3600x3000 at scale 3)
  if (isNaN(width) || isNaN(height) || isNaN(scale) || width < 100 || width > 1200 || height < 100 || height > 1000 || scale < 1 || scale > 4) {
    console.log(`[SCREENSHOT] Invalid dimensions: w=${width} h=${height} scale=${scale}`);
    return c.json({ error: "Invalid dimensions" }, 400);
  }

  const cleanUsername = username.replace(/^@/, '').trim().toLowerCase();
  if (!/^[a-zA-Z0-9_]{1,15}$/.test(cleanUsername)) {
    return c.json({ error: "Invalid username format" }, 400);
  }

  // Only allow screenshots for cached profiles (prevents X API calls)
  const profileCached = await databaseManager.getCachedProfile(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
    cleanUsername
  );
  if (!profileCached) {
    return c.json({ error: "Profile not cached. View the profile first." }, 404);
  }

  // Build cache key: username_widthxheight_scale_theme
  const cacheKey = `${cleanUsername}_${width}x${height}_${scale}_${theme}`;

  // Check screenshot cache first
  const cachedScreenshot = await databaseManager.getCachedImage(
    currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString,
    cacheKey
  );
  if (cachedScreenshot && Date.now() - cachedScreenshot.cached_at < SCREENSHOT_CACHE_TTL) {
    console.log(`[SCREENSHOT] Cache hit for ${cacheKey}`);
    return c.body(cachedScreenshot.image, 200, {
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${cleanUsername}-qr.png"`,
      'Cache-Control': 'no-store'
    });
  }

  const browser = await getBrowser();
  if (!browser) {
    return c.json({ error: "Screenshot service unavailable" }, 503);
  }

  let context = null;
  try {
    console.log(`[SCREENSHOT] Generating ${cleanUsername} @ ${width}x${height} scale ${scale} ${theme} (WebKit)`);

    // Only allow navigation to localhost (security: never hit external sites)
    const baseUrl = isDevelopment ? 'http://localhost:5173' : `http://localhost:${port}`;
    const targetUrl = `${baseUrl}/app/home?u=${cleanUsername}&screenshot=1&t=${Date.now()}`;

    // Validate URL is localhost only
    const parsedUrl = new URL(targetUrl);
    if (parsedUrl.hostname !== 'localhost') {
      console.error(`[SCREENSHOT] Blocked non-localhost URL: ${targetUrl}`);
      return c.json({ error: "Invalid target" }, 400);
    }

    // Create context from persistent browser (much faster than launching new browser)
    context = await browser.newContext({
      viewport: { width, height },
      deviceScaleFactor: scale,
      bypassCSP: true,
      colorScheme: theme,
    });
    // Disable caching
    await context.route('**/*', route => route.continue());
    await context.addInitScript(() => {
      // Force no caching
      if (window.caches) window.caches.keys().then(keys => keys.forEach(k => caches.delete(k)));
    });
    const page = await context.newPage();

    await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 30000 });

    // Wait for profile content to render (canvas = QR code is ready)
    try {
      await page.waitForSelector('canvas', { timeout: 10000 });
      // Wait for fonts to load
      await page.evaluate(() => document.fonts.ready);
      await new Promise(r => setTimeout(r, 500));
    } catch (e) {
      console.log('[SCREENSHOT] Canvas not found, taking screenshot anyway');
    }

    const screenshot = await page.screenshot({ type: 'png' });
    await context.close();
    context = null;
    screenshotCount++;

    console.log(`[SCREENSHOT] Generated ${cleanUsername} - ${screenshot.length} bytes (count: ${screenshotCount})`);

    // Cache the screenshot for future requests
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
    console.error("Screenshot error:", error.message);
    if (context) await context.close();
    return c.json({ error: "Failed to generate image" }, 500);
  }
});

// Auth routes
app.post("/signup", authLimiter, async (c) => {
  try {
    const body = await c.req.json();
    let { email, password, name } = body;

    if (!validateEmail(email)) {
      return c.json({ error: 'Invalid email format' }, 400);
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
    const insertID = generateUUID();

    try {
      await databaseManager.insertUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, {
        _id: insertID,
        email,
        name,
        created_at: Date.now()
      });

      const token = await generateToken(insertID);
      await databaseManager.insertAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, {
        email, password: hash, userID: insertID
      });

      const csrfToken = generateCSRFToken();
      csrfTokenStore.set(insertID.toString(), { token: csrfToken, timestamp: Date.now() });

      setCookie(c, 'token', token, {
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
        path: '/',
        maxAge: tokenExpirationDays * 24 * 60 * 60
      });

      console.log(`[${new Date().toISOString()}] Signup success: ${email}`);

      return c.json({
        id: insertID.toString(),
        email,
        name,
        tokenExpires: tokenExpireTimestamp(),
        csrfToken
      }, 201);
    } catch (e) {
      if (e.message?.includes('UNIQUE constraint failed') || e.code === 11000) {
        return c.json({ error: "Unable to create account with provided credentials" }, 400);
      }
      throw e;
    }
  } catch (e) {
    console.error(`Signup error:`, e.message);
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/signin", authLimiter, async (c) => {
  try {
    const body = await c.req.json();
    let { email, password } = body;

    if (!validateEmail(email) || !password) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    email = email.toLowerCase().trim();

    const auth = await databaseManager.findAuth(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { email });
    if (!auth || !(await verifyPassword(password, auth.password))) {
      return c.json({ error: "Invalid credentials" }, 401);
    }

    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { email });
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    const token = await generateToken(user._id.toString());
    const csrfToken = generateCSRFToken();
    csrfTokenStore.set(user._id.toString(), { token: csrfToken, timestamp: Date.now() });

    setCookie(c, 'token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
      path: '/',
      maxAge: tokenExpirationDays * 24 * 60 * 60
    });

    console.log(`[${new Date().toISOString()}] Signin success: ${email}`);

    return c.json({
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      ...(user.subscription && { subscription: user.subscription }),
      tokenExpires: tokenExpireTimestamp(),
      csrfToken
    });
  } catch (e) {
    console.error(`Signin error:`, e.message);
    return c.json({ error: "Server error" }, 500);
  }
});

app.post("/signout", authMiddleware, async (c) => {
  const userID = c.get('userID');
  csrfTokenStore.delete(userID);
  deleteCookie(c, 'token', { path: '/' });
  console.log(`[${new Date().toISOString()}] Signout: ${userID}`);
  return c.json({ message: "Signed out successfully" });
});

// User data routes
app.get("/me", authMiddleware, async (c) => {
  const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: c.get('userID') });
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json(user);
});

app.put("/me", authMiddleware, csrfProtection, async (c) => {
  try {
    const userID = c.get('userID');
    const body = await c.req.json();

    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    if (!user) return c.json({ error: "User not found" }, 404);

    const UPDATEABLE_FIELDS = ['name'];
    const update = {};
    for (const [key, value] of Object.entries(body)) {
      if (UPDATEABLE_FIELDS.includes(key)) {
        update[key] = typeof value === 'string' ? escapeHtml(value.trim()) : value;
      }
    }

    if (Object.keys(update).length === 0) {
      return c.json({ error: "No valid fields to update" }, 400);
    }

    await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID }, { $set: update });
    const updatedUser = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    return c.json(updatedUser);
  } catch (err) {
    console.error("Update user error:", err);
    return c.json({ error: "Failed to update user" }, 500);
  }
});

// Usage tracking
app.post("/usage", authMiddleware, async (c) => {
  try {
    const body = await c.req.json();
    const { operation } = body;
    const userID = c.get('userID');

    if (!operation || !['check', 'track'].includes(operation)) {
      return c.json({ error: "Invalid operation" }, 400);
    }

    const user = await databaseManager.findUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID });
    if (!user) return c.json({ error: "User not found" }, 404);

    const isSubscriber = user.subscription?.status === 'active' &&
      (!user.subscription?.expires || user.subscription.expires > Math.floor(Date.now() / 1000));

    if (isSubscriber) {
      return c.json({ remaining: -1, total: -1, isSubscriber: true });
    }

    const limit = parseInt(process.env.FREE_USAGE_LIMIT || '20');
    const now = Math.floor(Date.now() / 1000);
    let usage = user.usage || { count: 0, reset_at: null };

    if (!usage.reset_at || now > usage.reset_at) {
      usage = { count: 0, reset_at: now + (30 * 24 * 60 * 60) };
      await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID }, { $set: { usage } });
    }

    if (operation === 'track') {
      if (usage.count >= limit) {
        return c.json({ error: "Usage limit reached", remaining: 0, total: limit, isSubscriber: false }, 429);
      }
      usage.count += 1;
      await databaseManager.updateUser(currentDbConfig.dbType, currentDbConfig.db, currentDbConfig.connectionString, { _id: userID }, { $set: { usage } });
    }

    return c.json({
      remaining: Math.max(0, limit - usage.count),
      total: limit,
      isSubscriber: false,
      used: usage.count
    });
  } catch (error) {
    console.error('Usage error:', error);
    return c.json({ error: "Server error" }, 500);
  }
});

// Cache headers for static assets (1 year for versioned assets)
app.use('/assets/*', async (c, next) => {
  await next();
  c.header('Cache-Control', 'public, max-age=31536000, immutable');
});

// Serve static files (built React app)
app.use('/*', serveStatic({ root: './backend/public' }));
app.get('*', serveStatic({ root: './backend/public', path: 'index.html' }));

// ==== UTILITY FUNCTIONS ====
function isProd() {
  return process.env.ENV === "production";
}

function loadLocalENV() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const envFilePath = resolve(__dirname, './.env');
  const envExamplePath = resolve(__dirname, './.env.example');

  try {
    statSync(envFilePath);
  } catch {
    try {
      const exampleData = readFileSync(envExamplePath, 'utf8');
      writeFileSync(envFilePath, exampleData);
    } catch {
      return;
    }
  }

  try {
    const data = readFileSync(envFilePath, 'utf8');
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
  } catch {}
}

// ==== SERVER STARTUP ====
const port = parseInt(process.env.PORT || "8000");

const server = serve({
  fetch: app.fetch,
  port,
  hostname: '::'
}, (info) => {
  console.log(`✅ Server running on port ${info.port}`);
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`${signal} received. Shutting down...`);
  server.close(async () => {
    if (persistentBrowser) {
      await persistentBrowser.close();
      console.log('Browser closed');
    }
    await databaseManager.closeAll();
    console.log('Database connections closed');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
