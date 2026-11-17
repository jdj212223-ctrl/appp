CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,            -- clean | rejected
  name TEXT, version TEXT, author TEXT, description TEXT,
  permissions TEXT,                -- JSON array
  report TEXT,                     -- JSON {verdict, kind, problems, warnings, notes}
  uploaded_at INTEGER, size INTEGER
);
CREATE INDEX IF NOT EXISTS apps_status ON apps(status, uploaded_at);
CREATE TABLE IF NOT EXISTS files (
  key TEXT PRIMARY KEY,            -- apps/<id>.appp, apps/<id>/app.json, icons/<id>.png
  type TEXT,
  data BLOB
);
