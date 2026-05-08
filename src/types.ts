export type AnalysisStatus = 'pending' | 'in_progress' | 'completed' | 'failed';

export type PhishScore = 'safe' | 'suspicious' | 'likely_phishing' | 'confirmed_phishing';

export interface UrlAnalysisResult {
  suspiciousKeywords: { keyword: string; found: boolean }[];
  typosquatScore: number;
  subdomainDepth: number;
  usesShortener: boolean;
  usesIpInsteadOfDomain: boolean;
  suspiciousTld: boolean;
  entropyScore: number;
  totalScore: number;
}

export interface DomAnalysisResult {
  hasLoginForm: boolean;
  hasPasswordField: boolean;
  hasSubmitButton: boolean;
  formCount: number;
  suspiciousInputs: { name: string; reason: string }[];
  externalForms: boolean;
  hasFavicon: boolean;
  hasTitle: boolean;
  scriptCount: number;
  externalScriptCount: number;
  hiddenElements: number;
  totalScore: number;
}

export interface LlmAnalysisResult {
  summary: string;
  riskLevel: string;
  indicators: string[];
  confidence: number;
  error?: string;
}

export interface PhishingReport {
  id: string;
  url: string;
  domain: string;
  status: AnalysisStatus;
  phishScore: PhishScore;
  urlAnalysis: UrlAnalysisResult | null;
  domAnalysis: DomAnalysisResult | null;
  llmAnalysis: LlmAnalysisResult | null;
  finalScore: number;
  created_at: string;
  completed_at: string | null;
  tags: string[];
}

export interface SubmitRequest {
  url: string;
  html?: string;
  enableLlm?: boolean;
  tags?: string[];
}
