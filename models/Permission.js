class Permission {
  constructor({
    id,
    name,
    description,
    createdAt = new Date()
  }) {
    this.id = id;
    this.name = name; // e.g., 'read', 'write', 'admin'
    this.description = description; // Optional description of what this permission allows
    this.createdAt = createdAt;
  }
}

module.exports = Permission;