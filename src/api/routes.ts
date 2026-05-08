import { Hono } from 'hono';
import { getDb } from '../db/init.js';
import { analyzeUrl } from '../analysis/url.js';
import { analyzeDom } from '../analysis/dom.js';
import { defaultLlmProvider } from '../analysis/llm.js';
import { PhishingReport, PhishScore, SubmitRequest } from '../types.js';

export const api = new Hono();

function generateId(): string {
  return `phish_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
}

function extractDomain(url: string): string {
  try { return new URL(url).hostname; }
  catch { return url; }
}

function computePhishScore(totalScore: number): PhishScore {
  if (totalScore >= 0.7) return 'confirmed_phishing';
  if (totalScore >= 0.4) return 'likely_phishing';
  if (totalScore >= 0.15) return 'suspicious';
  return 'safe';
}

api.get('/health', (c) => {
  const db = getDb();
  try {
    const total = (db.prepare('SELECT COUNT(*) as c FROM reports').get() as { c: number }).c;
    db.close();
    return c.json({ status: 'ok', reports: total, uptime: process.uptime() });
  } catch (err) {
    db.close();
    return c.json({ status: 'error', error: String(err) }, 500);
  }
});

api.post('/analyze', async (c) => {
  const body = await c.req.json() as SubmitRequest;
  if (!body.url) return c.json({ error: 'url is required' }, 400);

  const id = generateId();
  const domain = extractDomain(body.url);
  const db = getDb();

  const urlResult = analyzeUrl(body.url);

  let domResult = null;
  if (body.html) {
    domResult = analyzeDom(body.html);
  }

  let llmResult = null;
  if (body.enableLlm) {
    llmResult = await defaultLlmProvider.analyze(body.url, urlResult, domResult);
  }

  let finalScore = urlResult.totalScore;
  if (domResult) finalScore = finalScore * 0.6 + domResult.totalScore * 0.4;
  if (llmResult && llmResult.confidence > 0 && !llmResult.error) {
    finalScore = finalScore * 0.7 + llmResult.confidence * 0.3;
  }
  finalScore = Math.round(finalScore * 100) / 100;

  const phishScore = computePhishScore(finalScore);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO reports (id, url, domain, status, phish_score, url_analysis, dom_analysis, llm_analysis, final_score, created_at, completed_at, tags)
    VALUES (?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, body.url, domain, phishScore,
    JSON.stringify(urlResult),
    domResult ? JSON.stringify(domResult) : null,
    llmResult ? JSON.stringify(llmResult) : null,
    finalScore, now, now,
    JSON.stringify(body.tags || [])
  );

  db.close();

  const report: PhishingReport = {
    id, url: body.url, domain, status: 'completed', phishScore,
    urlAnalysis: urlResult,
    domAnalysis: domResult,
    llmAnalysis: llmResult,
    finalScore, created_at: now, completed_at: now,
    tags: body.tags || [],
  };

  return c.json(report, 201);
});

api.get('/reports', (c) => {
  const db = getDb();
  const score = c.req.query('minScore');
  const status = c.req.query('status');
  const domain = c.req.query('domain');
  const limit = Math.min(Number(c.req.query('limit')) || 50, 500);
  const offset = Number(c.req.query('offset')) || 0;

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  if (score) { where += ' AND final_score >= ?'; params.push(Number(score)); }
  if (status) { where += ' AND status = ?'; params.push(status); }
  if (domain) { where += ' AND domain LIKE ?'; params.push(`%${domain}%`); }

  const total = (db.prepare(`SELECT COUNT(*) as c FROM reports ${where}`).get(...params) as { c: number }).c;
  const rows = db.prepare(`SELECT * FROM reports ${where} ORDER BY final_score DESC, created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset) as any[];

  db.close();

  const reports = rows.map(row => ({
    id: row.id,
    url: row.url,
    domain: row.domain,
    status: row.status,
    phishScore: row.phish_score,
    urlAnalysis: JSON.parse(row.url_analysis || 'null'),
    domAnalysis: JSON.parse(row.dom_analysis || 'null'),
    llmAnalysis: JSON.parse(row.llm_analysis || 'null'),
    finalScore: row.final_score,
    created_at: row.created_at,
    completed_at: row.completed_at,
    tags: JSON.parse(row.tags || '[]'),
  }));

  return c.json({ reports, total, query: { score, status, domain, limit, offset } });
});

api.get('/reports/:id', (c) => {
  const db = getDb();
  const row = db.prepare('SELECT * FROM reports WHERE id = ?').get(c.req.param('id')) as any;
  db.close();
  if (!row) return c.json({ error: 'Report not found' }, 404);

  return c.json({
    id: row.id,
    url: row.url,
    domain: row.domain,
    status: row.status,
    phishScore: row.phish_score,
    urlAnalysis: JSON.parse(row.url_analysis || 'null'),
    domAnalysis: JSON.parse(row.dom_analysis || 'null'),
    llmAnalysis: JSON.parse(row.llm_analysis || 'null'),
    finalScore: row.final_score,
    created_at: row.created_at,
    completed_at: row.completed_at,
    tags: JSON.parse(row.tags || '[]'),
  });
});

api.get('/stats', (c) => {
  const db = getDb();
  const total = (db.prepare('SELECT COUNT(*) as c FROM reports').get() as { c: number }).c;
  const byScore = db.prepare('SELECT phish_score, COUNT(*) as count FROM reports GROUP BY phish_score ORDER BY count DESC').all();
  const topDomains = db.prepare('SELECT domain, COUNT(*) as count FROM reports GROUP BY domain ORDER BY count DESC LIMIT 20').all();
  const avgScore = (db.prepare('SELECT AVG(final_score) as avg FROM reports').get() as { avg: number }).avg;
  const recentHigh = db.prepare("SELECT * FROM reports WHERE phish_score IN ('likely_phishing','confirmed_phishing') ORDER BY created_at DESC LIMIT 10").all() as any[];
  db.close();

  return c.json({
    total,
    byScore,
    topDomains,
    averageScore: Math.round(avgScore * 100) / 100,
    recentHighRisk: recentHigh.map(r => ({
      id: r.id, url: r.url, domain: r.domain, phishScore: r.phish_score, finalScore: r.final_score, created_at: r.created_at,
    })),
  });
});
