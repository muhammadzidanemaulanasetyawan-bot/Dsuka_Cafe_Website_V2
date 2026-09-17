'use strict';

const http = require('http');
const fs   = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// ============================================================
// SERVER CONFIGURATION
// ============================================================
const PORT    = process.env.PORT || 3000;
const WEB_ROOT = path.resolve(__dirname);
const DB_PATH = path.resolve(__dirname, 'dsuka.sqlite');

// Inisialisasi koneksi Database
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[ERROR] Gagal terhubung ke database:', err.message);
  } else {
    console.log('[INFO] Terhubung ke database SQLite.');
  }
});

// ============================================================
// SECURITY: Allowed File Extensions (Whitelist)
// Only these file types may be served to the client.
// ============================================================
const ALLOWED_EXTENSIONS = new Set([
  '.html', '.css', '.js', '.json',
  '.png', '.jpg', '.jpeg', '.gif',
  '.svg', '.ico', '.webp', '.txt',
]);

// ============================================================
// SECURITY: Blocked Sensitive Files
// These files must never be served regardless of extension.
// ============================================================
const BLOCKED_FILES = new Set([
  'server.js',
  'init_db.js',
  'dsuka.sqlite',
  'package.json',
  'package-lock.json',
  '.env',
  '.env.local',
  '.gitignore',
  'node_modules',
]);

// ============================================================
// MIME TYPES
// ============================================================
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
  '.txt':  'text/plain; charset=utf-8',
};

// ============================================================
// SECURITY: HTTP Security Headers
// Applied to every response to protect against common attacks.
// ============================================================
const SECURITY_HEADERS = {
  // Prevent browsers from guessing content type
  'X-Content-Type-Options': 'nosniff',

  // Block the page from being embedded in iframes (Clickjacking protection)
  'X-Frame-Options': 'DENY',

  // Enable browser's built-in XSS filter (legacy browsers)
  'X-XSS-Protection': '1; mode=block',

  // Control referrer information sent on navigation
  'Referrer-Policy': 'strict-origin-when-cross-origin',

  // ── [HTTPS / SSL Requirement] ──────────────────────────────────────────
  // PENTING: Pastikan website di-hosting menggunakan HTTPS (SSL/TLS).
  // Jika sudah pakai HTTPS di production, aktifkan HSTS di bawah ini:
  // 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',

  // Restrict browser feature access
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',

  // Content Security Policy — tightly scoped to only what this site needs
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",           // inline JS in index.html
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; '),

  // Do not expose server technology
  'Server': 'WebServer',

  // Cache control for HTML (always revalidate)
  'Cache-Control': 'no-cache, no-store, must-revalidate',
};

// ============================================================
// SECURITY: Rate Limiting (in-memory, per IP)
// Max 100 requests per 60 seconds per IP address.
// ============================================================
const RATE_LIMIT_MAX      = 100;  // max requests
const RATE_LIMIT_WINDOW   = 60 * 1000; // 60 seconds in ms
const rateLimitStore      = new Map(); // { ip: { count, resetAt } }

// Periodically clean up expired rate limit entries to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of rateLimitStore.entries()) {
    if (now > data.resetAt) rateLimitStore.delete(ip);
  }
}, RATE_LIMIT_WINDOW);

/**
 * Checks if the given IP has exceeded the rate limit.
 * Returns true if the request is allowed, false if blocked.
 * @param {string} ip
 * @returns {boolean}
 */
function isRateLimitAllowed(ip) {
  const now = Date.now();
  let record = rateLimitStore.get(ip);

  if (!record || now > record.resetAt) {
    // New window: reset counter
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }

  record.count++;
  if (record.count > RATE_LIMIT_MAX) return false;
  return true;
}

/**
 * Gets the real client IP, accounting for reverse proxies.
 * @param {http.IncomingMessage} req
 * @returns {string}
 */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // x-forwarded-for can be comma-separated list; take the first
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// ============================================================
// SECURITY: Apply all security headers to a response
// ============================================================
function applySecurityHeaders(res, extra = {}) {
  const headers = Object.assign({}, SECURITY_HEADERS, extra);
  for (const [key, value] of Object.entries(headers)) {
    res.setHeader(key, value);
  }
}

// ============================================================
// SECURITY: Safe error responses (no internal info leaked)
// ============================================================
function send403(res) {
  applySecurityHeaders(res);
  res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!DOCTYPE html><html><body><h1>403 Forbidden</h1></body></html>');
}

function send404(res) {
  applySecurityHeaders(res);
  res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>');
}

function send429(res) {
  applySecurityHeaders(res, { 'Retry-After': '60' });
  res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!DOCTYPE html><html><body><h1>429 Too Many Requests</h1><p>Please try again later.</p></body></html>');
}

function send500(res) {
  applySecurityHeaders(res);
  res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!DOCTYPE html><html><body><h1>500 Internal Server Error</h1></body></html>');
}

// ============================================================
// Helper: Membaca request body JSON
// ============================================================
function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch (e) { reject(e); }
    });
  });
}

// ============================================================
// STATIC FILE SERVER & API ROUTES WITH SECURITY HARDENING
// ============================================================
const server = http.createServer(async (req, res) => {
  const clientIP = getClientIP(req);

  // ── [1] Rate Limiting ───────────────────────────────────────
  if (!isRateLimitAllowed(clientIP)) {
    console.warn(`[SECURITY] Rate limit exceeded — IP: ${clientIP}`);
    send429(res);
    return;
  }

  // ── [3] Parse & Decode Request Path Safely ─────────────────
  let rawPath;
  try {
    rawPath = decodeURIComponent(req.url.split('?')[0]);
  } catch (e) {
    send403(res);
    return;
  }

  // ── [API] Dynamic Backend Routes ───────────────────────────
  if (rawPath.startsWith('/api/')) {
    applySecurityHeaders(res);
    
    if (req.method === 'GET' && rawPath === '/api/menu') {
      db.all('SELECT * FROM menu_items', (err, rows) => {
        if (err) return send500(res);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(rows));
      });
      return;
    }
    
    if (req.method === 'POST' && rawPath === '/api/reservations') {
      try {
        const body = await getRequestBody(req);
        const { nama, wa, tanggal, jam, pax, tempat, catatan } = body;
        
        // Simpan ke database
        const stmt = db.prepare(`INSERT INTO reservations (customer_name, wa_number, res_date, res_time, pax, seating, notes) VALUES (?, ?, ?, ?, ?, ?, ?)`);
        stmt.run([nama, wa, tanggal, jam, pax, tempat, catatan], function(err) {
          if (err) return send500(res);
          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, id: this.lastID }));
        });
        stmt.finalize();
      } catch (err) {
        send500(res);
      }
      return;
    }
    
    // API Route tidak ditemukan
    send404(res);
    return;
  }

  // ── [2] Only Allow GET and HEAD for Static Files ───────────
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    applySecurityHeaders(res);
    res.writeHead(405, { 'Content-Type': 'text/plain', 'Allow': 'GET, HEAD' });
    res.end('405 Method Not Allowed');
    return;
  }

  // ── [4] Resolve Absolute File Path ─────────────────────────
  const filePath = path.resolve(WEB_ROOT, rawPath === '/' ? 'index.html' : rawPath.slice(1));

  // ── [5] Path Traversal Protection ──────────────────────────
  // Ensure the resolved path is strictly inside WEB_ROOT
  if (!filePath.startsWith(WEB_ROOT + path.sep) && filePath !== WEB_ROOT) {
    console.warn(`[SECURITY] Path traversal attempt — IP: ${clientIP} PATH: ${rawPath}`);
    send403(res);
    return;
  }

  // ── [6] Blocked Sensitive File Protection ──────────────────
  const fileName = path.basename(filePath);
  if (BLOCKED_FILES.has(fileName) || fileName.startsWith('.')) {
    console.warn(`[SECURITY] Blocked sensitive file request — IP: ${clientIP} FILE: ${fileName}`);
    send403(res);
    return;
  }

  // ── [7] File Extension Whitelist ───────────────────────────
  const ext = path.extname(filePath).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    console.warn(`[SECURITY] Disallowed file extension — IP: ${clientIP} EXT: ${ext}`);
    send403(res);
    return;
  }

  // ── [8] Determine Content-Type ─────────────────────────────
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  // ── [9] Serve the File ─────────────────────────────────────
  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        send404(res);
      } else {
        // Log internally but don't expose details to client
        console.error(`[ERROR] File read error — ${err.code}`);
        send500(res);
      }
      return;
    }

    // Set cache headers: long cache for assets, no-cache for HTML
    const cacheControl = ext === '.html'
      ? 'no-cache, no-store, must-revalidate'
      : 'public, max-age=86400'; // 1 day for static assets

    applySecurityHeaders(res, { 'Cache-Control': cacheControl });
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(content);
  });
});

// ============================================================
// START SERVER
// ============================================================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[INFO] D'Suka Cafe website is running at http://localhost:${PORT}/`);
  console.log(`[INFO] Security features: Rate Limiting | Security Headers | Path Traversal Protection | File Whitelist`);
});
