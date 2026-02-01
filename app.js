require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const db = require('./db');

console.log('DB loaded successfully');

const app = express();

// CORS middleware for development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.use(express.json());
app.use(express.static('public'));

// Helper function to log usage
function logUsage(apiKeyId, action, endpoint, ip, userAgent, metadata) {
  try {
    const stmt = db.prepare(`
      INSERT INTO usage_records (api_key_id, action, endpoint, ip, user_agent, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(apiKeyId, action, endpoint, ip, userAgent, JSON.stringify(metadata));
  } catch (error) {
    console.error('Error logging usage:', error);
  }
}

// Health endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});
console.log('Route registered: GET /health');

// Create API key endpoint
app.post('/api-keys', (req, res) => {
  try {
    const { owner, scopes = [], expiration } = req.body;

    if (!owner) {
      return res.status(400).json({ error: 'Owner is required' });
    }

    // Validate scopes - should be an array of strings in format 'resource:action'
    if (!Array.isArray(scopes) || !scopes.every(s => typeof s === 'string' && s.includes(':'))) {
      return res.status(400).json({ error: 'Scopes must be an array of strings in format "resource:action" (e.g., "orders:read")' });
    }

    // Generate cryptographically secure random key (32 bytes, hex encoded = 64 chars)
    const key = crypto.randomBytes(32).toString('hex');

    // Generate unique salt for this key
    const salt = crypto.randomBytes(16).toString('hex');

    // Hash the key using scrypt (secure key derivation function)
    const keyHash = crypto.scryptSync(key, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');

    // Insert into database
    const stmt = db.prepare(`
      INSERT INTO api_keys (key_hash, salt, status, expiration, created_at, updated_at, scopes, owner)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const now = new Date().toISOString();
    const info = stmt.run(
      keyHash,
      salt,
      'active',
      expiration || null,
      now,
      now,
      JSON.stringify(scopes),
      owner
    );

    // Return the plaintext key only once
    res.status(201).json({
      id: info.lastInsertRowid,
      key, // Plaintext key - returned only once
      owner,
      scopes,
      expiration: expiration || null,
      status: 'active',
      created_at: now
    });

  } catch (error) {
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: POST /api-keys');

// List all API keys endpoint (excludes soft-deleted keys)
app.get('/api-keys', (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT id, owner, scopes, status, expiration, created_at, updated_at
      FROM api_keys
      WHERE deleted_at IS NULL
      ORDER BY created_at DESC
    `);
    const keys = stmt.all().map(key => ({
      ...key,
      scopes: JSON.parse(key.scopes)
    }));
    res.json(keys);
  } catch (error) {
    console.error('Error listing API keys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: GET /api-keys');

// Revoke API key endpoint
app.patch('/api-keys/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (status !== 'revoked') {
      return res.status(400).json({ error: 'Only status "revoked" is allowed for updates' });
    }

    const now = new Date().toISOString();
    const stmt = db.prepare(`
      UPDATE api_keys
      SET status = ?, updated_at = ?
      WHERE id = ?
    `);
    const info = stmt.run(status, now, id);

    if (info.changes === 0) {
      return res.status(404).json({ error: 'API key not found' });
    }

    res.json({ id: parseInt(id), status: 'revoked', updated_at: now });
  } catch (error) {
    console.error('Error revoking API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: PATCH /api-keys/:id');

// Soft delete API key endpoint
app.delete('/api-keys/:id', (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();

    const stmt = db.prepare(`
      UPDATE api_keys
      SET deleted_at = ?, updated_at = ?
      WHERE id = ? AND deleted_at IS NULL
    `);
    const info = stmt.run(now, now, id);

    if (info.changes === 0) {
      return res.status(404).json({ error: 'API key not found or already deleted' });
    }

    res.json({ id: parseInt(id), deleted_at: now });
  } catch (error) {
    console.error('Error soft deleting API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: DELETE /api-keys/:id');

// Validate API key endpoint
app.post('/validate', (req, res) => {
  try {
    const { apiKey, scope, service } = req.body;

    if (!apiKey || !scope || !service) {
      return res.status(400).json({ error: 'apiKey, scope, and service are required' });
    }

    // Validate scope format
    if (!scope.includes(':')) {
      return res.status(400).json({ error: 'Scope must be in format "resource:action"' });
    }

    // Find the API key by checking all non-deleted keys
    const stmt = db.prepare(`
      SELECT id, key_hash, salt, status, expiration, scopes, owner
      FROM api_keys
      WHERE deleted_at IS NULL
    `);

    const keys = stmt.all();
    let keyData = null;

    for (const key of keys) {
      const computedHash = crypto.scryptSync(apiKey, key.salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
      if (computedHash === key.key_hash) {
        keyData = key;
        break;
      }
    }

    if (!keyData) {
      // Log usage
      logUsage(null, 'validate', '/validate', req.ip, req.get('User-Agent'), { service, scope, result: 'invalid_key' });
      return res.json({ allowed: false, reason: 'Invalid API key' });
    }
    const scopes = JSON.parse(keyData.scopes);

    // Check status
    if (keyData.status !== 'active') {
      logUsage(keyData.id, 'validate', '/validate', req.ip, req.get('User-Agent'), { service, scope, result: 'revoked' });
      return res.json({ allowed: false, reason: 'API key is revoked' });
    }

    // Check expiration
    if (keyData.expiration && new Date(keyData.expiration) < new Date()) {
      logUsage(keyData.id, 'validate', '/validate', req.ip, req.get('User-Agent'), { service, scope, result: 'expired' });
      return res.json({ allowed: false, reason: 'API key has expired' });
    }

    // Check scope
    if (!scopes.includes(scope)) {
      logUsage(keyData.id, 'validate', '/validate', req.ip, req.get('User-Agent'), { service, scope, result: 'insufficient_scope' });
      return res.json({ allowed: false, reason: 'Insufficient scope' });
    }

    // Success
    logUsage(keyData.id, 'validate', '/validate', req.ip, req.get('User-Agent'), { service, scope, result: 'allowed' });
    res.json({
      allowed: true,
      metadata: {
        keyId: keyData.id,
        owner: keyData.owner,
        scopes: scopes,
        service: service,
        validatedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Error validating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: POST /validate');

// Get usage analytics for a specific API key (includes deleted keys for auditing)
app.get('/api-keys/:id/usage', (req, res) => {
  try {
    const { id } = req.params;

    const stmt = db.prepare(`
      SELECT ur.id, ur.timestamp, ur.action, ur.endpoint, ur.ip, ur.user_agent, ur.metadata,
             ak.owner, ak.status, ak.deleted_at
      FROM usage_records ur
      LEFT JOIN api_keys ak ON ur.api_key_id = ak.id
      WHERE ur.api_key_id = ?
      ORDER BY ur.timestamp DESC
    `);

    const records = stmt.all(id).map(record => ({
      ...record,
      metadata: JSON.parse(record.metadata || '{}')
    }));

    res.json({
      keyId: parseInt(id),
      totalRequests: records.length,
      keyInfo: records.length > 0 ? {
        owner: records[0].owner,
        status: records[0].status,
        deleted_at: records[0].deleted_at
      } : null,
      records: records
    });
  } catch (error) {
    console.error('Error fetching usage analytics:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
console.log('Route registered: GET /api-keys/:id/usage');

const port = process.env.PORT || 3000;

// Function to print registered routes
function printRoutes() {
  console.log('Registered routes:');
  if (app._router && app._router.stack) {
    app._router.stack.forEach((middleware) => {
      if (middleware.route) {
        const methods = Object.keys(middleware.route.methods).join(', ').toUpperCase();
        console.log(`  ${methods} ${middleware.route.path}`);
      } else if (middleware.name === 'serveStatic') {
        console.log('  Static files served');
      }
    });
  } else {
    console.log('  Unable to list routes (Express 5 internal structure)');
  }
}

if (require.main === module) {
  printRoutes();
  app.listen(port, () => {
    console.log(`API Manager service running on port ${port}`);
  });
}

module.exports = app;