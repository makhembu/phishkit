import { LlmAnalysisResult, UrlAnalysisResult, DomAnalysisResult } from '../types.js';

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

async function callLlmApi(prompt: string, apiUrl: string, apiKey: string): Promise<string> {
  const res = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 300,
      temperature: 0.3,
    }),
  });

  if (!res.ok) throw new Error(`LLM API returned ${res.status}`);
  const data = await res.json() as any;
  return data.choices?.[0]?.message?.content || '';
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

export const defaultLlmProvider: LlmProvider = {
  analyze: async (url, urlResult, domResult): Promise<LlmAnalysisResult> => {
    const apiUrl = process.env.LLM_API_URL;
    const apiKey = process.env.LLM_API_KEY;

    if (!apiUrl || !apiKey) {
      return {
        summary: 'LLM analysis unavailable: API not configured',
        riskLevel: 'unknown',
        indicators: [],
        confidence: 0,
        error: 'LLM_API_URL or LLM_API_KEY not set',
      };
    }

    try {
      const prompt = buildPrompt(url, urlResult, null);
      const response = await callLlmApi(prompt, apiUrl, apiKey);
      return parseLlmResponse(response);
    } catch (err: any) {
      return {
        summary: 'LLM analysis failed',
        riskLevel: 'unknown',
        indicators: [],
        confidence: 0,
        error: err.message,
      };
    }
  },
};
