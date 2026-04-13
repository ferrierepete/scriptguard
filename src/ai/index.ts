/** ScriptGuard — AI module exports */

export { GeminiClient, getGeminiClient, resetGeminiClient } from './gemini-client.js';
export { buildPrompt, sanitizeForPrompt } from './prompts.js';
export {
  analyzeFalsePositives,
  getFalsePositiveConfidence,
} from './analyzers/false-positive-filter.js';
export {
  detectAdvancedThreats,
} from './analyzers/threat-detector.js';
export {
  generateInsights,
} from './analyzers/insight-generator.js';

// Re-export types for convenience
export type {
  AIOptions,
  AIMode,
  AIAnalysis,
  AIInsight,
  AIBatchRequest,
  AIBatchResponse,
} from '../types/index.js';
