import { LlmAnalysisResult, UrlAnalysisResult, DomAnalysisResult } from '../types.js';

type LlmProviderType = 'zen' | 'gemini' | 'custom';

interface LlmProvider {
  analyze: (url: string, urlResult: UrlAnalysisResult, domResult: DomAnalysisResult | null) => Promise<LlmAnalysisResult>;
}

function buildPrompt(url: string, urlResult: UrlAnalysisResult, domHtml: string | null): string {
  let prompt = `Analyze this URL for phishing characteristics:\nURL: ${url}\n\nURL Analysis:\n`;
  prompt += `- Suspicious keywords found: ${urlResult.suspiciousKeywords.filter(k => k.found).map(k => k.keyword).join(', ') || 'none'}\n`;
  prompt += `- Typosquatting score: ${urlResult.typosquatScore}\n`;
  prompt += `- Subdomain depth: ${urlResult.subdomainDepth}\n`;
  prompt += `- Uses URL shortener: ${urlResult.usesShortener}\n`;
  prompt += `- Uses raw IP: ${urlResult.usesIpInsteadOfDomain}\n`;
  prompt += `- Suspicious TLD: ${urlResult.suspiciousTld}\n`;
  prompt += `- Overall URL score: ${urlResult.totalScore}\n`;

  if (domHtml) {
    prompt += `\nDOM Analysis provided (${domHtml.length} chars).\n`;
  }

  prompt += `\nProvide:\n1. Risk level (safe/suspicious/likely_phishing/confirmed_phishing)\n2. Brief summary (1-2 sentences)\n3. Key indicators observed\n4. Confidence score (0-1)`;
  return prompt;
}

function parseLlmResponse(text: string): LlmAnalysisResult {
  const lower = text.toLowerCase();
  let riskLevel = 'suspicious';
  if (lower.includes('confirmed_phishing') || lower.includes('confirmed phishing')) riskLevel = 'confirmed_phishing';
  else if (lower.includes('likely_phishing') || lower.includes('likely phishing')) riskLevel = 'likely_phishing';
  else if (lower.includes('suspicious')) riskLevel = 'suspicious';
  else if (lower.includes('safe')) riskLevel = 'safe';

  const confidenceMatch = text.match(/confidence.*?([0-9.]+)/i);
  const confidence = confidenceMatch ? Math.min(1, Math.max(0, parseFloat(confidenceMatch[1]))) : 0.5;

  const indicators: string[] = [];
  const lines = text.split('\n');
  let inIndicators = false;
  for (const line of lines) {
    if (/indicators?:|observations?:|flags?:/i.test(line)) inIndicators = true;
    else if (inIndicators && /^\s*[-*]\s/.test(line)) indicators.push(line.replace(/^\s*[-*]\s*/, '').trim());
    else if (inIndicators && /^\d+\./.test(line)) indicators.push(line.replace(/^\d+\.\s*/, '').trim());
    else if (inIndicators && line.trim() === '') inIndicators = false;
  }

  return {
    summary: text.split('\n').slice(0, 3).join(' ').trim().slice(0, 300),
    riskLevel,
    indicators,
    confidence,
  };
}

async function callZenApi(prompt: string): Promise<string> {
  const apiKey = process.env.ZEN_API_KEY || 'sk-u8mPctB6o43VPBTszjsy14D38yQGCWahMpYlNXSviU8s1mbjfY7dmUnvlhv6Pz3j';
  const model = process.env.ZEN_MODEL || 'big-pickle';
  const baseUrl = process.env.ZEN_API_URL || 'https://opencode.ai/zen/v1/chat/completions';

  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], max_tokens: 300, temperature: 0.3 }),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    throw new Error(`Zen API returned ${res.status}: ${errBody.slice(0, 200)}`);
  }

  const data = await res.json() as any;
  const content = data.choices?.[0]?.message?.content;
  if (!content) {
    const reasoning = data.choices?.[0]?.message?.reasoning_content;
    if (reasoning) return `Reasoning: ${reasoning}\nRisk level: suspicious\nConfidence: 0.3`;
    throw new Error('Zen API returned empty response');
  }
  return content;
}

async function callGeminiApi(prompt: string): Promise<string> {
  const apiKey = process.env.GEMINI_API_KEY || 'AIzaSyAx2I32ntgKzE9MvJtxdFccQzU28RHoKiU';
  const model = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
  const baseUrl = process.env.GEMINI_API_URL || `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  const res = await fetch(`${baseUrl}?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 300, temperature: 0.3 } }),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    throw new Error(`Gemini API returned ${res.status}: ${errBody.slice(0, 200)}`);
  }

  const data = await res.json() as any;
  const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) throw new Error('Gemini API returned empty response');
  return text;
}

async function callCustomApi(prompt: string): Promise<string> {
  const apiUrl = process.env.LLM_API_URL;
  const apiKey = process.env.LLM_API_KEY;
  const model = process.env.LLM_MODEL || 'gpt-4o-mini';

  if (!apiUrl || !apiKey) throw new Error('LLM_API_URL or LLM_API_KEY not set');

  const res = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], max_tokens: 300, temperature: 0.3 }),
  });

  if (!res.ok) throw new Error(`LLM API returned ${res.status}`);
  const data = await res.json() as any;
  return data.choices?.[0]?.message?.content || '';
}

async function tryProviders(prompt: string): Promise<string> {
  const providers: { name: LlmProviderType; fn: (p: string) => Promise<string> }[] = [
    { name: 'zen', fn: callZenApi },
    { name: 'gemini', fn: callGeminiApi },
  ];

  const preferred = (process.env.LLM_PROVIDER || 'zen') as LlmProviderType;
  if (preferred === 'custom') {
    return callCustomApi(prompt);
  }

  const ordered = preferred === 'gemini' ? providers.reverse() : providers;
  const errors: string[] = [];

  for (const provider of ordered) {
    try {
      const result = await provider.fn(prompt);
      return result;
    } catch (err: any) {
      errors.push(`${provider.name}: ${err.message}`);
    }
  }

  throw new Error(`All providers failed: ${errors.join('; ')}`);
}

export const defaultLlmProvider: LlmProvider = {
  analyze: async (url, urlResult, _domResult): Promise<LlmAnalysisResult> => {
    try {
      const prompt = buildPrompt(url, urlResult, null);
      const response = await tryProviders(prompt);
      return parseLlmResponse(response);
    } catch (err: any) {
      return {
        summary: 'LLM analysis unavailable',
        riskLevel: 'unknown',
        indicators: [],
        confidence: 0,
        error: err.message,
      };
    }
  },
};
