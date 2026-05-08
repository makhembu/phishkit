import { UrlAnalysisResult } from '../types.js';

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'update', 'confirm',
  'secure', 'banking', 'paypal', 'password', 'credential',
  'authenticate', 'reset', 'recover', 'validate', 'suspend',
  'unlock', 'billing', 'invoice', 'webmail', 'webscr',
];

const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl',
  'is.gd', 'cli.gs', 'ow.ly', 'buff.ly', 'tiny.cc',
  'rebrand.ly', 'cutt.ly', 'shorte.st', 'adf.ly',
];

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
  '.club', '.work', '.date', '.men', '.loan', '.download',
  '.review', '.stream', '.trade', '.bid',
];

const BRAND_DOMAINS = [
  'google', 'facebook', 'apple', 'microsoft', 'amazon',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
  'dropbox', 'adobe', 'spotify', 'whatsapp', 'youtube',
  'github', 'slack', 'discord', 'telegram', 'outlook',
];

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

function checkTyposquatting(domain: string): number {
  let score = 0;
  const lower = domain.split('.')[0];

  for (const brand of BRAND_DOMAINS) {
    const dist = levenshtein(lower, brand);
    if (dist === 0) return 0;
    if (dist === 1) score += 0.8;
    else if (dist <= 2) score += 0.5;
    else if (dist <= 3) score += 0.2;
  }

  if (lower.includes('-') && BRAND_DOMAINS.some(b => lower.includes(b))) score += 0.4;
  const brandInSubdomain = BRAND_DOMAINS.some(b => domain.split('.').slice(1).some(p => p.includes(b)));
  if (brandInSubdomain) score += 0.6;

  return Math.min(score, 1);
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function checkKeywords(url: string): { keyword: string; found: boolean }[] {
  const lower = url.toLowerCase();
  return SUSPICIOUS_KEYWORDS.map(k => ({ keyword: k, found: lower.includes(k) }));
}

export function analyzeUrl(url: string): UrlAnalysisResult {
  const domain = extractDomain(url);
  let totalScore = 0;

  const suspiciousKeywords = checkKeywords(url);
  const keywordHits = suspiciousKeywords.filter(k => k.found).length;

  const typosquatScore = checkTyposquatting(domain);
  const subdomainDepth = domain.split('.').length - 2;
  const usesShortener = SHORTENER_DOMAINS.some(s => domain.includes(s));
  const usesIpInsteadOfDomain = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
  const suspiciousTld = SUSPICIOUS_TLDS.some(t => domain.endsWith(t));

  const urlPath = url.includes('://') ? new URL(url).pathname + new URL(url).search : '';
  const entropyScore = calculateEntropy(urlPath || domain);

  if (keywordHits > 0) totalScore += Math.min(keywordHits * 0.15, 0.6);
  totalScore += typosquatScore * 0.5;
  totalScore += Math.min(subdomainDepth * 0.1, 0.3);
  if (usesShortener) totalScore += 0.4;
  if (usesIpInsteadOfDomain) totalScore += 0.7;
  if (suspiciousTld) totalScore += 0.3;
  if (entropyScore > 4) totalScore += 0.2;

  return {
    suspiciousKeywords,
    typosquatScore,
    subdomainDepth,
    usesShortener,
    usesIpInsteadOfDomain,
    suspiciousTld,
    entropyScore: Math.round(entropyScore * 100) / 100,
    totalScore: Math.round(totalScore * 100) / 100,
  };
}

if (process.argv[1]?.endsWith('url.ts') || process.argv[1]?.endsWith('url.js')) {
  const testUrl = process.argv[2] || 'https://secure-login-paypal.com.verify-account.tk/login';
  console.log('Analyzing URL:', testUrl);
  console.log(JSON.stringify(analyzeUrl(testUrl), null, 2));
}
