import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { getSchema } from './schema.js';

const DB_PATH = process.env.DB_PATH || './data/phishkit.db';

export function getDb(): Database.Database {
  const dbDir = path.dirname(DB_PATH);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

export function initDb(): void {
  const db = getDb();
  db.exec(getSchema());
  console.log('[phishkit] Database initialized at', DB_PATH);
  db.close();
}

if (process.argv[1]?.endsWith('init.ts') || process.argv[1]?.endsWith('init.js')) {
  initDb();
}
