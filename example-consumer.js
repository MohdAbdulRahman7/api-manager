const express = require('express');
const app = express();

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Middleware to validate API key against required scope
function validateApiKey(apiManagerUrl, requiredScope, serviceName) {
  return async (req, res, next) => {
    try {
      console.log(`Validating request to ${req.path} for scope ${requiredScope}`);

      // Extract API key from Authorization header
      const authHeader = req.headers.authorization || req.headers['Authorization'];
      console.log('Auth header present:', !!authHeader);
      console.log('Auth header value:', authHeader ? authHeader.substring(0, 20) + '...' : 'none');

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('Invalid or missing auth header');
        return res.status(401).json({ error: 'Missing or invalid Authorization header. Use: Authorization: Bearer <api-key>' });
      }

      const apiKey = authHeader.substring(7).trim(); // Remove 'Bearer ' and trim
      console.log('Extracted API key length:', apiKey.length);

      if (!apiKey) {
        console.log('Empty API key after extraction');
        return res.status(401).json({ error: 'Empty API key in Authorization header' });
      }

      // Call the API manager validation endpoint
      console.log(`Calling validation endpoint: ${apiManagerUrl}/validate`);
      const response = await fetch(`${apiManagerUrl}/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: apiKey,
          scope: requiredScope,
          service: serviceName
        })
      });

      console.log('Validation response status:', response.status);
      const result = await response.json();
      console.log('Validation result:', result);

      if (!result.allowed) {
        console.log('Access denied:', result.reason);
        return res.status(403).json({
          error: 'Access denied',
          reason: result.reason
        });
      }

      console.log('Access granted for key:', result.metadata.keyId);
      // Attach validation metadata to request for downstream use
      req.apiKeyValidation = result.metadata;

      next();
    } catch (error) {
      console.error('API key validation error:', error);
      res.status(500).json({ error: 'Internal server error during validation' });
    }
  };
}

// Example usage in an Express app
app.use(express.json());

// Protected route that requires 'orders:read' scope
app.get('/orders', validateApiKey('http://localhost:3000', 'orders:read', 'order-service'), (req, res) => {
  res.json({
    message: 'Orders data',
    accessedBy: req.apiKeyValidation.owner,
    keyId: req.apiKeyValidation.keyId,
    timestamp: new Date().toISOString()
  });
});

// Another protected route that requires 'inventory:write' scope
app.post('/inventory', validateApiKey('http://localhost:3000', 'inventory:write', 'inventory-service'), (req, res) => {
  res.json({
    message: 'Inventory updated',
    accessedBy: req.apiKeyValidation.owner,
    keyId: req.apiKeyValidation.keyId,
    timestamp: new Date().toISOString()
  });
});

// Public route (no validation required)
app.get('/health', (req, res) => {
  res.json({ status: 'Consumer service is healthy' });
});

const port = 3001;
app.listen(port, () => {
  console.log(`Example consumer service running on port ${port}`);
  console.log('Try:');
  console.log('GET /health');
  console.log('GET /orders (requires Bearer <api-key> with orders:read scope)');
  console.log('POST /inventory (requires Bearer <api-key> with inventory:write scope)');
});

module.exports = { validateApiKey };