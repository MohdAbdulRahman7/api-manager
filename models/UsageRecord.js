class UsageRecord {
  constructor({
    id,
    apiKeyId,
    timestamp = new Date(),
    action, // e.g., 'validate', 'use', 'issue', 'revoke'
    endpoint, // The endpoint accessed
    ip, // IP address of the request
    userAgent, // User agent string
    metadata = {} // Additional metadata, e.g., request body hash, response code
  }) {
    this.id = id;
    this.apiKeyId = apiKeyId;
    this.timestamp = timestamp;
    this.action = action;
    this.endpoint = endpoint;
    this.ip = ip;
    this.userAgent = userAgent;
    this.metadata = metadata;
  }
}

module.exports = UsageRecord;