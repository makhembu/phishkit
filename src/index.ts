import { serve } from '@hono/node-server';
import { api } from './api/routes.js';
import { initDb } from './db/init.js';
import { Hono } from 'hono';

const app = new Hono();

app.route('/', api);

app.get('/', (c) => {
  return c.json({
    name: 'PhishKit — Phishing Analysis Pipeline',
    version: '1.0.0',
    description: 'URL pattern analysis, DOM structure inspection, and LLM-assisted phishing assessment',
    docs: {
      health: 'GET /health',
      analyze: 'POST /analyze { url, html?, enableLlm?, tags? }',
      reports: 'GET /reports?minScore=&status=&domain=&limit=&offset=',
      reportDetail: 'GET /reports/:id',
      stats: 'GET /stats',
    },
  });
});

const PORT = Number(process.env.PORT) || 3002;

initDb();

console.log(`[phishkit] Starting server on port ${PORT}`);
serve({ fetch: app.fetch, port: PORT });

export default app;
