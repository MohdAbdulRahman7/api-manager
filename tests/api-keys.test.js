const request = require('supertest');
const app = require('../app');
const db = require('../db');

describe('API Keys Endpoints', () => {
  beforeEach(() => {
    // Clear the api_keys table before each test
    db.exec('DELETE FROM api_keys');
  });

  describe('POST /api-keys', () => {
    it('should create a new API key successfully', async () => {
      const payload = {
        owner: 'test-user',
        scopes: ['orders:read', 'inventory:write'],
        expiration: '2024-12-31T23:59:59Z'
      };

      const res = await request(app)
        .post('/api-keys')
        .send(payload)
        .expect(201);

      expect(res.body).toHaveProperty('id');
      expect(res.body).toHaveProperty('key');
      expect(res.body.key).toMatch(/^[a-f0-9]{64}$/); // 32 bytes hex = 64 chars
      expect(res.body.owner).toBe('test-user');
      expect(res.body.scopes).toEqual(['orders:read', 'inventory:write']);
      expect(res.body.status).toBe('active');
      expect(res.body.expiration).toBe('2024-12-31T23:59:59Z');
      expect(res.body).toHaveProperty('created_at');
    });

    it('should create API key with default values', async () => {
      const payload = { owner: 'test-user' };

      const res = await request(app)
        .post('/api-keys')
        .send(payload)
        .expect(201);

      expect(res.body.scopes).toEqual([]);
      expect(res.body.expiration).toBeNull();
    });

    it('should return 400 if owner is missing', async () => {
      const payload = { permissions: ['read'] };

      const res = await request(app)
        .post('/api-keys')
        .send(payload)
        .expect(400);

      expect(res.body.error).toBe('Owner is required');
    });

    it('should return 400 if scopes is not an array of valid strings', async () => {
      const payload = { owner: 'test-user', scopes: ['read', 123] };

      const res = await request(app)
        .post('/api-keys')
        .send(payload)
        .expect(400);

      expect(res.body.error).toBe('Scopes must be an array of strings in format "resource:action" (e.g., "orders:read")');
    });
  });

  describe('GET /api-keys', () => {
    it('should return empty array when no keys exist', async () => {
      const res = await request(app)
        .get('/api-keys')
        .expect(200);

      expect(res.body).toEqual([]);
    });

    it('should return list of API keys without sensitive data', async () => {
      // Create a key first
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);

      const res = await request(app)
        .get('/api-keys')
        .expect(200);

      expect(res.body).toHaveLength(1);
      expect(res.body[0]).toHaveProperty('id', createRes.body.id);
      expect(res.body[0]).toHaveProperty('owner', 'test-user');
      expect(res.body[0]).toHaveProperty('scopes', ['orders:read']);
      expect(res.body[0]).toHaveProperty('status', 'active');
      expect(res.body[0]).toHaveProperty('created_at');
      expect(res.body[0]).toHaveProperty('updated_at');
      expect(res.body[0]).not.toHaveProperty('key');
      expect(res.body[0]).not.toHaveProperty('key_hash');
    });
  });

  describe('PATCH /api-keys/:id', () => {
    it('should revoke an API key', async () => {
      // Create a key first
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user' })
        .expect(201);

      const res = await request(app)
        .patch(`/api-keys/${createRes.body.id}`)
        .send({ status: 'revoked' })
        .expect(200);

      expect(res.body).toHaveProperty('id', createRes.body.id);
      expect(res.body).toHaveProperty('status', 'revoked');
      expect(res.body).toHaveProperty('updated_at');

      // Verify in list
      const listRes = await request(app)
        .get('/api-keys')
        .expect(200);

      expect(listRes.body[0].status).toBe('revoked');
    });

    it('should return 404 for non-existent key', async () => {
      const res = await request(app)
        .patch('/api-keys/999')
        .send({ status: 'revoked' })
        .expect(404);

      expect(res.body.error).toBe('API key not found');
    });

    it('should return 400 for invalid status', async () => {
      // Create a key first
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user' })
        .expect(201);

      const res = await request(app)
        .patch(`/api-keys/${createRes.body.id}`)
        .send({ status: 'active' })
        .expect(400);

      expect(res.body.error).toBe('Only status "revoked" is allowed for updates');
    });
  });

  describe('DELETE /api-keys/:id', () => {
    it('should soft delete an API key', async () => {
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);

      const deleteRes = await request(app)
        .delete(`/api-keys/${createRes.body.id}`)
        .expect(200);

      expect(deleteRes.body).toHaveProperty('id', createRes.body.id);
      expect(deleteRes.body).toHaveProperty('deleted_at');

      // Should not appear in list
      const listRes = await request(app)
        .get('/api-keys')
        .expect(200);

      expect(listRes.body.find(k => k.id === createRes.body.id)).toBeUndefined();

      // But should still be validatable? No, since deleted_at IS NULL check
      // Actually, in validate, we check deleted_at IS NULL, so deleted keys won't be found
    });

    it('should return 404 for already deleted key', async () => {
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);

      await request(app)
        .delete(`/api-keys/${createRes.body.id}`)
        .expect(200);

      const res = await request(app)
        .delete(`/api-keys/${createRes.body.id}`)
        .expect(404);

      expect(res.body.error).toBe('API key not found or already deleted');
    });
  });

  describe('POST /validate', () => {
    it('should allow valid API key with correct scope', async () => {
      // Create a test key
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read', 'inventory:write'] })
        .expect(201);
      const testKey = createRes.body.key;
      const testKeyId = createRes.body.id;

      const res = await request(app)
        .post('/validate')
        .send({ apiKey: testKey, scope: 'orders:read', service: 'order-service' })
        .expect(200);

      expect(res.body.allowed).toBe(true);
      expect(res.body.metadata).toHaveProperty('keyId', testKeyId);
      expect(res.body.metadata).toHaveProperty('owner', 'test-user');
      expect(res.body.metadata.scopes).toEqual(['orders:read', 'inventory:write']);
      expect(res.body.metadata).toHaveProperty('service', 'order-service');
    });

    it('should deny invalid API key', async () => {
      const res = await request(app)
        .post('/validate')
        .send({ apiKey: 'invalid-key', scope: 'orders:read', service: 'order-service' })
        .expect(200);

      expect(res.body.allowed).toBe(false);
      expect(res.body.reason).toBe('Invalid API key');
    });

    it('should deny revoked API key', async () => {
      // Create a test key
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);
      const testKey = createRes.body.key;

      // Revoke the key
      await request(app)
        .patch(`/api-keys/${createRes.body.id}`)
        .send({ status: 'revoked' })
        .expect(200);

      const res = await request(app)
        .post('/validate')
        .send({ apiKey: testKey, scope: 'orders:read', service: 'order-service' })
        .expect(200);

      expect(res.body.allowed).toBe(false);
      expect(res.body.reason).toBe('API key is revoked');
    });

    it('should deny insufficient scope', async () => {
      // Create a test key with limited scopes
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);
      const testKey = createRes.body.key;

      const res = await request(app)
        .post('/validate')
        .send({ apiKey: testKey, scope: 'inventory:write', service: 'inventory-service' })
        .expect(200);

      expect(res.body.allowed).toBe(false);
      expect(res.body.reason).toBe('Insufficient scope');
    });

    it('should return 400 for missing parameters', async () => {
      const res = await request(app)
        .post('/validate')
        .send({ scope: 'orders:read', service: 'order-service' })
        .expect(400);

      expect(res.body.error).toBe('apiKey, scope, and service are required');
    });

    it('should return 400 for invalid scope format', async () => {
      const res = await request(app)
        .post('/validate')
        .send({ apiKey: 'dummy', scope: 'invalid-scope', service: 'order-service' })
        .expect(400);

      expect(res.body.error).toBe('Scope must be in format "resource:action"');
    });
  });

  describe('GET /api-keys/:id/usage', () => {
    it('should return usage analytics for a valid key', async () => {
      // Create a key
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);
      const keyId = createRes.body.id;

      // Make some validation requests to generate usage
      await request(app)
        .post('/validate')
        .send({ apiKey: createRes.body.key, scope: 'orders:read', service: 'test-service' });

      await request(app)
        .post('/validate')
        .send({ apiKey: createRes.body.key, scope: 'orders:read', service: 'test-service' });

      const res = await request(app)
        .get(`/api-keys/${keyId}/usage`)
        .expect(200);

      expect(res.body).toHaveProperty('keyId', keyId);
      expect(res.body).toHaveProperty('totalRequests', 2);
      expect(res.body.records).toHaveLength(2);
      expect(res.body.records[0]).toHaveProperty('action', 'validate');
      expect(res.body.records[0]).toHaveProperty('metadata');
      expect(res.body.records[0].metadata).toHaveProperty('service', 'test-service');
      expect(res.body.records[0].metadata).toHaveProperty('scope', 'orders:read');
    });

    it('should return empty analytics for key with no usage', async () => {
      const createRes = await request(app)
        .post('/api-keys')
        .send({ owner: 'test-user', scopes: ['orders:read'] })
        .expect(201);

      const res = await request(app)
        .get(`/api-keys/${createRes.body.id}/usage`)
        .expect(200);

      expect(res.body).toHaveProperty('keyId', createRes.body.id);
      expect(res.body).toHaveProperty('totalRequests', 0);
      expect(res.body.records).toEqual([]);
    });
  });
});