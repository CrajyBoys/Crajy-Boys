// db.js — simple SQLite helper (initializes DB and exposes a run/get/all wrapped API)
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'crajy_members.db');

const db = new sqlite3.Database(DB_PATH);

function init() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      dob TEXT,
      verified INTEGER DEFAULT 0,
      password_hash TEXT,
      token_hash TEXT,
      token_expiry INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )`);
  });
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

module.exports = { init, run, get, all, db };
