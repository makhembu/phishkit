const SCHEMA = `
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','in_progress','completed','failed')),
  phish_score TEXT NOT NULL DEFAULT 'safe' CHECK(phish_score IN ('safe','suspicious','likely_phishing','confirmed_phishing')),
  url_analysis TEXT,
  dom_analysis TEXT,
  llm_analysis TEXT,
  final_score REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  tags TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_score ON reports(final_score);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
`;

export function getSchema(): string {
  return SCHEMA;
}
