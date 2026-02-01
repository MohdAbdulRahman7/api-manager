const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'api_manager.db');

let db;
try {
  db = new Database(dbPath);

  // Enable foreign keys
  db.pragma('foreign_keys = ON');

  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      expiration TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      deleted_at TEXT, -- Soft delete timestamp
      scopes TEXT DEFAULT '[]', -- JSON array of scope strings like 'orders:read'
      owner TEXT
    );

    CREATE TABLE IF NOT EXISTS usage_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      api_key_id INTEGER,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
      action TEXT,
      endpoint TEXT,
      ip TEXT,
      user_agent TEXT,
      metadata TEXT, -- JSON
      FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
    );
  `);
} catch (error) {
  console.error('Error initializing database:', error);
  process.exit(1);
}

module.exports = db;