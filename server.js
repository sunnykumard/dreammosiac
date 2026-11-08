const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const db = require('./db');
const auth = require('./auth');

const PORT = process.env.PORT || 3001;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const THUMBS_DIR = path.join(__dirname, 'uploads', 'thumbs');
const PROJECTS_DIR = path.join(__dirname, 'uploads', 'projects');

// Ensure directories exist
for (const dir of [UPLOADS_DIR, THUMBS_DIR, PROJECTS_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// Helpers
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach((cookie) => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

function sendJson(res, statusCode, data, headers = {}) {
  const json = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...headers
  });
  res.end(json);
}

function sendError(res, statusCode, message, details = {}) {
  sendJson(res, statusCode, { error: message, ...details });
}

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket.remoteAddress ||
    '127.0.0.1'
  );
}

// Parse request body (JSON or raw buffer)
function parseBody(req, limit = 50 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Request entity too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      const contentType = req.headers['content-type'] || '';
      if (contentType.includes('application/json')) {
        try {
          const parsed = JSON.parse(buffer.toString('utf-8'));
          resolve(parsed);
        } catch (e) {
          reject(new Error('Invalid JSON'));
        }
      } else {
        resolve(buffer);
      }
    });
    req.on('error', reject);
  });
}

// Authentication middleware
async function getAuthContext(req) {
  const cookies = parseCookies(req);
  let token = cookies['dm_session'];

  if (!token && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) return null;
  return await auth.validateSession(token);
}

const server = http.createServer(async (req, res) => {
  // CORS & Security headers
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  try {
    // ------------------------------------------------------------------------
    // Public Status Endpoint
    // ------------------------------------------------------------------------
    if (pathname === '/api/status' && req.method === 'GET') {
      const isConfigured = await auth.isSystemConfigured();
      const user = await getAuthContext(req);
      return sendJson(res, 200, {
        status: 'online',
        name: 'DreamMosaic API',
        version: '1.0.0',
        isConfigured,
        requiresSetup: !isConfigured,
        authenticated: !!user,
        user: user ? { role: user.role, label: user.label } : null
      });
    }

    // ------------------------------------------------------------------------
    // Initial Setup Endpoint (Only works if not configured)
    // ------------------------------------------------------------------------
    if (pathname === '/api/auth/setup' && req.method === 'POST') {
      try {
        const credentials = await auth.performInitialSetup();
        return sendJson(res, 200, {
          success: true,
          message: 'DreamMosaic keys generated securely. Store them safely.',
          ...credentials
        });
      } catch (err) {
        return sendError(res, 400, err.message);
      }
    }

    // ------------------------------------------------------------------------
    // Key Login Endpoint (Rate limited, HttpOnly cookie)
    // ------------------------------------------------------------------------
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await parseBody(req);
      const key = body.key;

      try {
        const result = await auth.authenticateWithKey(key, ip, userAgent);
        
        // Set secure HttpOnly cookie
        const isSecure = req.connection.encrypted ? 'Secure;' : '';
        const cookieHeader = `dm_session=${result.token}; HttpOnly; ${isSecure} SameSite=Strict; Path=/; Max-Age=${7 * 24 * 3600}`;

        return sendJson(
          res,
          200,
          {
            success: true,
            user: result.user,
            token: result.token,
            expiresAt: result.expiresAt
          },
          { 'Set-Cookie': cookieHeader }
        );
      } catch (err) {
        return sendError(res, err.status || 401, err.message, {
          waitSeconds: err.waitSeconds
        });
      }
    }

    // ------------------------------------------------------------------------
    // Session Verification Endpoint
    // ------------------------------------------------------------------------
    if (pathname === '/api/auth/session' && req.method === 'GET') {
      const user = await getAuthContext(req);
      if (!user) {
        return sendError(res, 401, 'Unauthorized or session expired');
      }
      return sendJson(res, 200, {
        authenticated: true,
        user: { role: user.role, label: user.label, keyId: user.keyId },
        expiresAt: user.expiresAt
      });
    }

    // ------------------------------------------------------------------------
    // Logout Endpoint
    // ------------------------------------------------------------------------
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const cookies = parseCookies(req);
      const token = cookies['dm_session'] || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
      if (token) {
        await auth.revokeSession(token);
      }
      const expiredCookie = `dm_session=; HttpOnly; Path=/; Max-Age=0`;
      return sendJson(res, 200, { success: true, message: 'Logged out' }, { 'Set-Cookie': expiredCookie });
    }

    // ------------------------------------------------------------------------
    // PROTECTED ROUTES BELOW (Require authenticated Owner or Partner)
    // ------------------------------------------------------------------------
    const user = await getAuthContext(req);
    if (!user) {
      return sendError(res, 401, 'Authentication required. Please provide a valid security key.');
    }

    // ------------------------------------------------------------------------
    // Owner-Only Security Management
    // ------------------------------------------------------------------------
    if (pathname === '/api/auth/keys' && req.method === 'GET') {
      try {
        const keys = await auth.listKeys(user.role);
        return sendJson(res, 200, { keys });
      } catch (err) {
        return sendError(res, err.status || 403, err.message);
      }
    }

    if (pathname === '/api/auth/keys/rotate' && req.method === 'POST') {
      const body = await parseBody(req);
      try {
        const result = await auth.rotateKey(body.role, user.role);
        return sendJson(res, 200, {
          success: true,
          message: `Security key for ${body.role} rotated successfully`,
          ...result
        });
      } catch (err) {
        return sendError(res, err.status || 403, err.message);
      }
    }

    if (pathname === '/api/auth/keys/revoke' && req.method === 'POST') {
      try {
        const result = await auth.revokePartnerKey(user.role);
        return sendJson(res, 200, {
          success: true,
          message: 'Partner security key has been revoked',
          ...result
        });
      } catch (err) {
        return sendError(res, err.status || 403, err.message);
      }
    }

    // ------------------------------------------------------------------------
    // Memory Statistics Endpoint
    // ------------------------------------------------------------------------
    if (pathname === '/api/stats' && req.method === 'GET') {
      const photoCount = await db.queryOne("SELECT count(*) as count, sum(file_size) as total_size FROM photos");
      const projectCount = await db.queryOne("SELECT count(*) as count FROM mosaic_projects");
      return sendJson(res, 200, {
        photosCount: photoCount.count || 0,
        totalBytes: photoCount.total_size || 0,
        projectsCount: projectCount.count || 0,
        userRole: user.role,
        userLabel: user.label
      });
    }

    // ------------------------------------------------------------------------
    // Photo Upload (Base64 data URL payload)
    // ------------------------------------------------------------------------
    if (pathname === '/api/photos/upload' && req.method === 'POST') {
      const body = await parseBody(req);
      const filename = (body.filename || `memory_${Date.now()}.jpg`).replace(/[^a-zA-Z0-9._-]/g, '_');
      const dataUrl = body.dataUrl || body.data;

      if (!dataUrl || typeof dataUrl !== 'string') {
        return sendError(res, 400, 'Invalid image data');
      }

      const match = dataUrl.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
      if (!match) {
        return sendError(res, 400, 'Data must be a valid base64 image data URL');
      }

      const ext = match[1].toLowerCase() === 'jpeg' ? 'jpg' : match[1].toLowerCase();
      const rawBuffer = Buffer.from(match[2], 'base64');
      const hashSha256 = crypto.createHash('sha256').update(rawBuffer).digest('hex');

      // Deduplication check
      const existing = await db.queryOne("SELECT * FROM photos WHERE hash_sha256 = ?", [hashSha256]);
      if (existing) {
        return sendJson(res, 200, {
          duplicate: true,
          message: 'Duplicate photo detected and skipped',
          photo: existing
        });
      }

      const photoId = 'photo_' + crypto.randomBytes(12).toString('hex');
      const storageFilename = `${photoId}.${ext}`;
      const storagePath = path.join(UPLOADS_DIR, storageFilename);
      const thumbFilename = `${photoId}_thumb.jpg`;
      const thumbPath = path.join(THUMBS_DIR, thumbFilename);

      // Save raw file
      fs.writeFileSync(storagePath, rawBuffer);

      // Process image for thumbnail and CIELAB
      let width = null;
      let height = null;
      let avgLab = [50, 0, 0];

      try {
        const helperPath = path.join(__dirname, 'image_helper.py');
        const output = execFileSync('python3', [helperPath, storagePath, thumbPath], {
          encoding: 'utf-8',
          timeout: 10000
        });
        const parsed = JSON.parse(output.trim());
        if (parsed.success) {
          width = parsed.width;
          height = parsed.height;
          avgLab = parsed.avg_lab;
        }
      } catch (imgErr) {
        console.warn('Image processing warning:', imgErr.message);
      }

      await db.exec(
        `INSERT INTO photos (id, filename, storage_path, thumbnail_path, file_size, mime_type, hash_sha256, width, height, avg_lab, uploaded_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          photoId,
          filename,
          storageFilename,
          thumbFilename,
          rawBuffer.length,
          `image/${ext}`,
          hashSha256,
          width,
          height,
          JSON.stringify(avgLab),
          user.role
        ]
      );

      const createdPhoto = await db.queryOne("SELECT * FROM photos WHERE id = ?", [photoId]);
      return sendJson(res, 201, {
        success: true,
        photo: {
          ...createdPhoto,
          avg_lab: JSON.parse(createdPhoto.avg_lab || '[50,0,0]')
        }
      });
    }

    // ------------------------------------------------------------------------
    // Photo Batch Upload (e.g. from ZIP or multiple selection)
    // ------------------------------------------------------------------------
    if (pathname === '/api/photos/upload-batch' && req.method === 'POST') {
      const body = await parseBody(req);
      const photosList = Array.isArray(body.photos) ? body.photos : [];
      let imported = 0;
      let duplicates = 0;
      const results = [];

      for (const item of photosList) {
        try {
          const match = item.dataUrl?.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
          if (!match) continue;
          const ext = match[1].toLowerCase() === 'jpeg' ? 'jpg' : match[1].toLowerCase();
          const rawBuffer = Buffer.from(match[2], 'base64');
          const hashSha256 = crypto.createHash('sha256').update(rawBuffer).digest('hex');

          const existing = await db.queryOne("SELECT id FROM photos WHERE hash_sha256 = ?", [hashSha256]);
          if (existing) {
            duplicates++;
            continue;
          }

          const photoId = 'photo_' + crypto.randomBytes(12).toString('hex');
          const storageFilename = `${photoId}.${ext}`;
          const storagePath = path.join(UPLOADS_DIR, storageFilename);
          const thumbFilename = `${photoId}_thumb.jpg`;
          const thumbPath = path.join(THUMBS_DIR, thumbFilename);

          fs.writeFileSync(storagePath, rawBuffer);

          let width = null;
          let height = null;
          let avgLab = item.avgLab || [50, 0, 0];

          try {
            const helperPath = path.join(__dirname, 'image_helper.py');
            const output = execFileSync('python3', [helperPath, storagePath, thumbPath], {
              encoding: 'utf-8',
              timeout: 10000
            });
            const parsed = JSON.parse(output.trim());
            if (parsed.success) {
              width = parsed.width;
              height = parsed.height;
              avgLab = parsed.avg_lab;
            }
          } catch (e) {}

          await db.exec(
            `INSERT INTO photos (id, filename, storage_path, thumbnail_path, file_size, mime_type, hash_sha256, width, height, avg_lab, uploaded_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              photoId,
              item.filename || `tile_${imported}.jpg`,
              storageFilename,
              thumbFilename,
              rawBuffer.length,
              `image/${ext}`,
              hashSha256,
              width,
              height,
              JSON.stringify(avgLab),
              user.role
            ]
          );

          imported++;
          results.push({ id: photoId, filename: item.filename, avg_lab: avgLab });
        } catch (itemErr) {
          console.warn('Batch photo error:', itemErr.message);
        }
      }

      return sendJson(res, 200, {
        success: true,
        imported,
        duplicates,
        total: photosList.length,
        photos: results
      });
    }

    // ------------------------------------------------------------------------
    // List Library Photos
    // ------------------------------------------------------------------------
    if (pathname === '/api/photos' && req.method === 'GET') {
      const photos = await db.query("SELECT * FROM photos ORDER BY created_at DESC");
      const mapped = photos.map((p) => ({
        ...p,
        avg_lab: JSON.parse(p.avg_lab || '[50,0,0]')
      }));
      return sendJson(res, 200, { photos: mapped });
    }

    // ------------------------------------------------------------------------
    // Authenticated Private Photo Access (Prevents public scraping)
    // ------------------------------------------------------------------------
    const photoMatch = pathname.match(/^\/api\/photos\/([a-zA-Z0-9_-]+)$/);
    if (photoMatch && req.method === 'GET') {
      const photoId = photoMatch[1];
      const photo = await db.queryOne("SELECT * FROM photos WHERE id = ?", [photoId]);
      if (!photo) return sendError(res, 404, 'Photo not found');

      const fullPath = path.join(UPLOADS_DIR, photo.storage_path);
      if (!fs.existsSync(fullPath)) return sendError(res, 404, 'File missing on disk');

      res.writeHead(200, {
        'Content-Type': photo.mime_type,
        'Cache-Control': 'private, no-cache, no-store, must-revalidate',
        'X-Content-Type-Options': 'nosniff'
      });
      return fs.createReadStream(fullPath).pipe(res);
    }

    // ------------------------------------------------------------------------
    // Authenticated Private Thumbnail Access
    // ------------------------------------------------------------------------
    const thumbMatch = pathname.match(/^\/api\/photos\/([a-zA-Z0-9_-]+)\/thumb$/);
    if (thumbMatch && req.method === 'GET') {
      const photoId = thumbMatch[1];
      const photo = await db.queryOne("SELECT * FROM photos WHERE id = ?", [photoId]);
      if (!photo) return sendError(res, 404, 'Photo not found');

      const fullThumbPath = path.join(THUMBS_DIR, photo.thumbnail_path);
      if (!fs.existsSync(fullThumbPath)) {
        // Fallback to original
        const fullPath = path.join(UPLOADS_DIR, photo.storage_path);
        if (!fs.existsSync(fullPath)) return sendError(res, 404, 'File missing');
        res.writeHead(200, { 'Content-Type': photo.mime_type, 'Cache-Control': 'private, max-age=86400' });
        return fs.createReadStream(fullPath).pipe(res);
      }

      res.writeHead(200, {
        'Content-Type': 'image/jpeg',
        'Cache-Control': 'private, max-age=86400',
        'X-Content-Type-Options': 'nosniff'
      });
      return fs.createReadStream(fullThumbPath).pipe(res);
    }

    // ------------------------------------------------------------------------
    // Delete Photo
    // ------------------------------------------------------------------------
    if (photoMatch && req.method === 'DELETE') {
      const photoId = photoMatch[1];
      const photo = await db.queryOne("SELECT * FROM photos WHERE id = ?", [photoId]);
      if (!photo) return sendError(res, 404, 'Photo not found');

      try {
        const fullPath = path.join(UPLOADS_DIR, photo.storage_path);
        const fullThumbPath = path.join(THUMBS_DIR, photo.thumbnail_path);
        if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
        if (fs.existsSync(fullThumbPath)) fs.unlinkSync(fullThumbPath);
      } catch (e) {}

      await db.exec("DELETE FROM photos WHERE id = ?", [photoId]);
      return sendJson(res, 200, { success: true, message: 'Photo deleted' });
    }

    // ------------------------------------------------------------------------
    // Mosaic Projects API (Save, List, Download, Delete)
    // ------------------------------------------------------------------------
    if (pathname === '/api/projects' && req.method === 'GET') {
      const projects = await db.query("SELECT * FROM mosaic_projects ORDER BY created_at DESC");
      return sendJson(res, 200, { projects });
    }

    if (pathname === '/api/projects' && req.method === 'POST') {
      const body = await parseBody(req);
      const projectId = 'proj_' + crypto.randomBytes(12).toString('hex');
      const title = body.title || `Our Romantic Mosaic ${new Date().toLocaleDateString()}`;

      // Save result PNG
      let resultFilename = null;
      if (body.resultDataUrl) {
        const match = body.resultDataUrl.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
        if (match) {
          resultFilename = `${projectId}_mosaic.png`;
          fs.writeFileSync(
            path.join(PROJECTS_DIR, resultFilename),
            Buffer.from(match[2], 'base64')
          );
        }
      }

      // Save target image if provided
      let targetFilename = body.targetPhotoStoragePath || '';
      if (body.targetDataUrl && !targetFilename) {
        const match = body.targetDataUrl.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
        if (match) {
          targetFilename = `${projectId}_target.jpg`;
          fs.writeFileSync(
            path.join(PROJECTS_DIR, targetFilename),
            Buffer.from(match[2], 'base64')
          );
        }
      }

      await db.exec(
        `INSERT INTO mosaic_projects (id, title, target_photo_id, target_storage_path, result_storage_path, tile_count, grid_cols, grid_rows, mode, settings_json, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          projectId,
          title,
          body.targetPhotoId || null,
          targetFilename,
          resultFilename,
          body.tileCount || 0,
          body.gridCols || 0,
          body.gridRows || 0,
          body.mode || 'classic',
          JSON.stringify(body.settings || {}),
          user.role
        ]
      );

      const project = await db.queryOne("SELECT * FROM mosaic_projects WHERE id = ?", [projectId]);
      return sendJson(res, 201, { success: true, project });
    }

    // Project Result Download
    const projResultMatch = pathname.match(/^\/api\/projects\/([a-zA-Z0-9_-]+)\/result$/);
    if (projResultMatch && req.method === 'GET') {
      const projectId = projResultMatch[1];
      const project = await db.queryOne("SELECT * FROM mosaic_projects WHERE id = ?", [projectId]);
      if (!project || !project.result_storage_path) return sendError(res, 404, 'Project result not found');

      const fullPath = path.join(PROJECTS_DIR, project.result_storage_path);
      if (!fs.existsSync(fullPath)) return sendError(res, 404, 'File missing');

      res.writeHead(200, {
        'Content-Type': 'image/png',
        'Content-Disposition': `attachment; filename="${project.title.replace(/[^a-zA-Z0-9_-]/g, '_')}_mosaic.png"`,
        'Cache-Control': 'private, no-cache'
      });
      return fs.createReadStream(fullPath).pipe(res);
    }

    // Delete Project
    const projMatch = pathname.match(/^\/api\/projects\/([a-zA-Z0-9_-]+)$/);
    if (projMatch && req.method === 'DELETE') {
      const projectId = projMatch[1];
      const project = await db.queryOne("SELECT * FROM mosaic_projects WHERE id = ?", [projectId]);
      if (!project) return sendError(res, 404, 'Project not found');

      try {
        if (project.result_storage_path) {
          const rPath = path.join(PROJECTS_DIR, project.result_storage_path);
          if (fs.existsSync(rPath)) fs.unlinkSync(rPath);
        }
      } catch (e) {}

      await db.exec("DELETE FROM mosaic_projects WHERE id = ?", [projectId]);
      return sendJson(res, 200, { success: true, message: 'Project deleted' });
    }

    // ------------------------------------------------------------------------
    // Static Files & PWA Serving (Non-API Routes)
    // ------------------------------------------------------------------------
    if (!pathname.startsWith('/api/')) {
      const publicDir = path.join(__dirname, 'public');
      let targetFile = 'index.html';
      let contentType = 'text/html';

      if (pathname === '/manifest.json') {
        targetFile = 'manifest.json';
        contentType = 'application/manifest+json';
      } else if (pathname === '/service-worker.js') {
        targetFile = 'service-worker.js';
        contentType = 'application/javascript';
      } else if (pathname === '/icon-192.png') {
        targetFile = 'icon-192.png';
        contentType = 'image/png';
      } else if (pathname === '/icon-512.png') {
        targetFile = 'icon-512.png';
        contentType = 'image/png';
      }

      const filePath = path.join(publicDir, targetFile);
      if (fs.existsSync(filePath)) {
        res.writeHead(200, {
          'Content-Type': contentType,
          'Cache-Control': targetFile.endsWith('.png') ? 'public, max-age=86400' : 'no-cache',
          'X-Content-Type-Options': 'nosniff'
        });
        return fs.createReadStream(filePath).pipe(res);
      }
    }

    // 404 for unknown API
    return sendError(res, 404, `Endpoint ${pathname} not found`);

  } catch (error) {
    console.error('Unhandled server error:', error);
    return sendError(res, 500, 'Internal Server Error', { details: error.message });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`DreamMosaic Backend Server running on http://0.0.0.0:${PORT}`);
});

module.exports = server;