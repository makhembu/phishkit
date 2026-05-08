import { DomAnalysisResult } from '../types.js';

const SUSPICIOUS_INPUT_NAMES = [
  'password', 'passwd', 'pwd', 'creditcard', 'ccnumber',
  'ssn', 'social', 'pin', 'atm', 'cvv', 'cvc',
  'bankaccount', 'routing', 'securitycode',
];

const FAKE_FIELD_PATTERNS = [
  'hidden', 'invisible', 'nofill', 'honeypot',
];

export function analyzeDom(html: string): DomAnalysisResult {
  const lower = html.toLowerCase();
  let totalScore = 0;

  const formMatches = lower.match(/<form[\s>]/g);
  const formCount = formMatches?.length || 0;

  const hasLoginForm = /(login|sign-?in|log-?in)/i.test(html);
  const hasPasswordField = /<input[^>]*type=["']?password["'\s>]/i.test(html);
  const hasSubmitButton = /<input[^>]*type=["']?submit["'\s>]/i.test(html) || /<button[^>]*type=["']?submit["'\s>]/i.test(html);

  const suspiciousInputs: { name: string; reason: string }[] = [];
  for (const name of SUSPICIOUS_INPUT_NAMES) {
    const pattern = new RegExp(`name=["']?${name}["'\\s>]`, 'i');
    if (pattern.test(html)) {
      suspiciousInputs.push({ name, reason: `Asks for sensitive field: ${name}` });
      totalScore += 0.15;
    }
  }

  const externalForms = /action=["']https?:\/\/(?!.*(?:\.?current-domain))/i.test(html) && formCount > 0;

  const hasFavicon = /<link[^>]*rel=["']?icon["'\s>]/i.test(html) || /<link[^>]*rel=["']?shortcut icon["'\s>]/i.test(html);
  const hasTitle = /<title[^>]*>.*?<\/title>/i.test(html);

  const scriptMatches = lower.match(/<script[\s>]/g);
  const scriptCount = scriptMatches?.length || 0;

  const externalScriptMatches = lower.match(/<script[^>]*src=["']https?:\/\//g);
  const externalScriptCount = externalScriptMatches?.length || 0;

  const hiddenMatches = lower.match(/style=["'][^"']*display:\s*none[^"']*["']/g);
  const hiddenElements = hiddenMatches?.length || 0;

  if (hasPasswordField) totalScore += 0.3;
  if (hasSubmitButton && hasPasswordField && !hasLoginForm) totalScore += 0.2;
  if (externalForms) totalScore += 0.5;
  if (!hasFavicon) totalScore += 0.05;
  if (!hasTitle) totalScore += 0.1;
  if (scriptCount > 10) totalScore += 0.2;
  if (hiddenElements > 3) totalScore += 0.2;

  return {
    hasLoginForm,
    hasPasswordField,
    hasSubmitButton,
    formCount,
    suspiciousInputs,
    externalForms,
    hasFavicon,
    hasTitle,
    scriptCount,
    externalScriptCount,
    hiddenElements,
    totalScore: Math.round(totalScore * 100) / 100,
  };
}
