# API Manager

A generic, standalone API key management service that any backend service (Node, Python, Go, internal or external) can use to issue, validate, and manage API keys with permissions.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file in the root directory with the following variables:
   ```
   PORT=3000
   ```

3. The service uses SQLite database (`api_manager.db`) which is created automatically on first run.

4. Run the service:
   ```bash
   npm start
   ```
   The server will log "Route registered" messages and confirm startup.

5. Access the test UI at `http://localhost:3000` to test all endpoints interactively.

6. Run tests:
   ```bash
   npm test
   ```

## Endpoints

- `GET /health`: Health check endpoint that returns `200 OK` if the service is running.
  ```bash
  curl http://localhost:3000/health
  ```

- `POST /api-keys`: Create a new API key. Requires `owner` in the request body. Optional: `permissions` (array of strings), `expiration` (ISO date string).
  ```bash
  curl -X POST http://localhost:3000/api-keys \
    -H "Content-Type: application/json" \
    -d '{"owner": "my-service", "permissions": ["read", "write"], "expiration": "2024-12-31T23:59:59Z"}'
  ```
  Returns the API key plaintext only once in the response.

- `GET /api-keys`: List all API keys with their metadata (excludes sensitive hash data).
  ```bash
  curl http://localhost:3000/api-keys
  ```

- `PATCH /api-keys/:id`: Revoke a specific API key by ID. Send `{"status": "revoked"}` in the request body.
  ```bash
  curl -X PATCH http://localhost:3000/api-keys/1 \
    -H "Content-Type: application/json" \
    -d '{"status": "revoked"}'
  ```
  Revoked keys remain stored for audit purposes but become immediately invalid.

- `POST /validate`: Validate an API key against a required scope and service. Returns allow/deny decision with metadata.
  ```bash
  curl -X POST http://localhost:3000/validate \
    -H "Content-Type: application/json" \
    -d '{"apiKey": "your-api-key", "scope": "orders:read", "service": "order-service"}'
  ```
  Response: `{"allowed": true, "metadata": {...}}` or `{"allowed": false, "reason": "..."}`

- `GET /api-keys/:id/usage`: Get usage analytics for a specific API key.
  ```bash
  curl http://localhost:3000/api-keys/1/usage
  ```
  Returns usage records with timestamps, actions, services, scopes, and results.

- `DELETE /api-keys/:id`: Soft delete an API key (marks as deleted but keeps for auditing).
  ```bash
  curl -X DELETE http://localhost:3000/api-keys/1
  ```
  Soft-deleted keys are hidden from lists but remain in analytics.

## Consumer Integration

The system is designed to be generic and decoupled. Any service can integrate by:

1. Extracting the API key from the `Authorization: Bearer <key>` header
2. Calling the `/validate` endpoint with the key, required scope, and service name
3. Allowing or denying access based on the response

See `example-consumer.js` for a complete Express middleware implementation that demonstrates this integration.

### Testing Consumer Integration

1. Start the API manager: `npm start`
2. Create an API key with scopes (e.g., `["orders:read", "inventory:write"]`)
3. In another terminal, start the consumer service: `node example-consumer.js`
4. Test with curl:
   ```bash
   curl -H "Authorization: Bearer <your-api-key>" http://localhost:3001/orders
   ```
   Or use the UI consumer demo at `http://localhost:3000` after ensuring both services are running.

Both services have CORS enabled for development testing. The consumer service logs detailed validation steps for debugging.

## Data Models

The service uses the following core data models:

- **ApiKey**: Represents an API key with fields for ID, hashed key, salt, status (active/revoked), expiration, creation/update/deletion timestamps, scopes array (e.g., "orders:read"), and owner. Supports soft deletion for audit preservation.
- **Permission**: Defines permissions/scopes with ID, name, description, and creation timestamp.
- **UsageRecord**: Tracks API key usage for auditing, including timestamp, action, endpoint, IP, user agent, and metadata.

These models are defined in the `models/` directory and provide methods for validation, revocation, and updates.

## Development

- Add new endpoints in `app.js`.
- Add corresponding tests in `tests/` directory.
- Use Jest for testing with Supertest for HTTP requests.
- Models are in `models/` directory; import from `models/index.js`.
