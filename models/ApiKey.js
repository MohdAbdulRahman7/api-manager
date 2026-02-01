class ApiKey {
  constructor({
    id,
    key,
    status = 'active',
    expiration,
    createdAt = new Date(),
    updatedAt = new Date(),
    scopes = [],
    owner
  }) {
    this.id = id;
    this.key = key;
    this.status = status; // 'active' or 'revoked'
    this.expiration = expiration; // Date object or null
    this.createdAt = createdAt;
    this.updatedAt = updatedAt;
    this.scopes = scopes; // Array of scope strings like 'orders:read'
    this.owner = owner; // String or ID of the owner
  }

  // Method to check if the key is valid
  isValid() {
    const now = new Date();
    return this.status === 'active' &&
           (!this.expiration || this.expiration > now);
  }

  // Method to revoke the key
  revoke() {
    this.status = 'revoked';
    this.updatedAt = new Date();
  }

  // Method to update scopes
  updateScopes(newScopes) {
    this.scopes = newScopes;
    this.updatedAt = new Date();
  }

  // Method to check if scope is allowed
  hasScope(scope) {
    return this.scopes.includes(scope);
  }
}

module.exports = ApiKey;