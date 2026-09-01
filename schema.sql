-- D1 schema. Run once:
--   npx wrangler d1 execute eem-letters --remote --file=./schema.sql
--
-- Note what is and is not readable here. `pending.v` holds the staged letter
-- as AES-256-GCM ciphertext, sealed with a key derived from the confirmation
-- token. That token lives only in the link in the reader's inbox, so a database
-- export contains nothing anyone can read — including us.

CREATE TABLE IF NOT EXISTS pending (
  k          TEXT    PRIMARY KEY,
  v          TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_expires ON pending (expires_at);

CREATE TABLE IF NOT EXISTS cache (
  k          TEXT    PRIMARY KEY,
  v          TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache (expires_at);

CREATE TABLE IF NOT EXISTS rate (
  k          TEXT    PRIMARY KEY,
  n          INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_expires ON rate (expires_at);

-- The only durable personal data. CASL requires proof of consent.
CREATE TABLE IF NOT EXISTS consent (
  email        TEXT    PRIMARY KEY,
  name         TEXT    NOT NULL,
  consented_at INTEGER NOT NULL,
  source       TEXT    NOT NULL,
  wording      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS stats (
  k TEXT    PRIMARY KEY,
  v INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS languages (
  name TEXT PRIMARY KEY
);

INSERT OR IGNORE INTO stats (k, v) VALUES ('letters', 0);
