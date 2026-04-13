/** ScriptGuard — Gemini AI client wrapper */

import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import type { AIMode, AIBatchRequest, AIBatchResponse } from '../types/index.js';

// Dynamic import for p-throttle to avoid ESM/CJS issues
let pThrottle: any;
async function getThrottle() {
  if (!pThrottle) {
    const module = await import('p-throttle');
    pThrottle = module.default || module;
  }
  return pThrottle;
}

// Rate limiting: 5 requests per second to stay within free tier limits
let throttle: any;

async function getThrottledGenerateContent() {
  if (!throttle) {
    const pThrottleModule = await getThrottle();
    throttle = pThrottleModule({
      limit: 5,
      interval: 1000,
    });
  }
  return throttle(async (model: GenerativeModel, prompt: string) => {
    return await model.generateContent(prompt);
  });
}

interface CacheEntry {
  response: AIBatchResponse;
  timestamp: number;
}

// In-memory cache with 24-hour TTL
const cache = new Map<string, CacheEntry>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export class GeminiClient {
  private client: GoogleGenerativeAI;
  private model: GenerativeModel;
  private totalTokensUsed = 0;

  constructor(apiKey?: string) {
    const key = apiKey || process.env.GOOGLE_AI_API_KEY;
    if (!key) {
      throw new Error(
        'GOOGLE_AI_API_KEY environment variable not set. ' +
        'Get your key at: https://makersuite.google.com/app/apikey'
      );
    }

    this.client = new GoogleGenerativeAI(key);
    this.model = this.client.getGenerativeModel({ model: 'gemini-3-flash-preview' });
  }

  /**
   * Sanitize script content before sending to API
   * Redacts API keys, tokens, and other sensitive data
   */
  private sanitizeScripts(scripts: Record<string, string>): Record<string, string> {
    const sanitized: Record<string, string> = {};

    for (const [name, content] of Object.entries(scripts)) {
      let cleaned = content;

      // Redact common secret patterns
      const secretPatterns = [
        /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?/gi,
        /bearer\s+[a-zA-Z0-9_\-]{20,}/gi,
        /sk-[a-zA-Z0-9]{48}/g, // OpenAI API keys
        /ghp_[a-zA-Z0-9]{36}/g, // GitHub tokens
        /gho_[a-zA-Z0-9]{36}/g, // GitHub OAuth tokens
        /ghu_[a-zA-Z0-9]{36}/g, // GitHub user tokens
        /ghs_[a-zA-Z0-9]{36}/g, // GitHub server tokens
        /ghr_[a-zA-Z0-9]{36}/g, // GitHub refresh tokens
        /xoxb-[0-9]{13}-[0-9]{13}-[a-zA-Z0-9]{24}/g, // Slack bot tokens
        /xoxp-[0-9]{13}-[0-9]{13}-[0-9]{12}-[a-zA-Z0-9]{24}/g, // Slack user tokens
        /AKIA[0-9A-Z]{16}/g, // AWS access keys
      ];

      for (const pattern of secretPatterns) {
        cleaned = cleaned.replace(pattern, '[REDACTED_SECRET]');
      }

      sanitized[name] = cleaned;
    }

    return sanitized;
  }

  /**
   * Generate cache key from request data
   */
  private getCacheKey(request: AIBatchRequest): string {
    const packagesHash = request.packages
      .map(p => `${p.name}@${p.version}:${Object.keys(p.scripts).join(',')}`)
      .sort()
      .join('|');
    return `${request.mode}:${packagesHash}`;
  }

  /**
   * Check cache for existing response
   */
  private getCachedResponse(cacheKey: string): AIBatchResponse | null {
    const cached = cache.get(cacheKey);
    if (!cached) return null;

    const now = Date.now();
    if (now - cached.timestamp > CACHE_TTL) {
      cache.delete(cacheKey);
      return null;
    }

    return cached.response;
  }

  /**
   * Cache a response
   */
  private setCachedResponse(cacheKey: string, response: AIBatchResponse): void {
    cache.set(cacheKey, {
      response,
      timestamp: Date.now(),
    });
  }

  /**
   * Get total tokens used across all requests
   */
  public getTotalTokensUsed(): number {
    return this.totalTokensUsed;
  }

  /**
   * Analyze a batch of packages using Gemini AI
   */
  public async analyzeBatch(request: AIBatchRequest): Promise<AIBatchResponse> {
    // Check cache first
    const cacheKey = this.getCacheKey(request);
    const cached = this.getCachedResponse(cacheKey);
    if (cached) {
      return cached;
    }

    // Import prompts dynamically
    const { buildPrompt } = await import('./prompts.js');

    // Sanitize all scripts before sending to API
    const sanitizedRequest = {
      ...request,
      packages: request.packages.map(pkg => ({
        ...pkg,
        scripts: this.sanitizeScripts(pkg.scripts),
      })),
    };

    // Build prompt based on mode
    const prompt = buildPrompt(sanitizedRequest, request.mode);

    try {
      // Call Gemini API with rate limiting
      const throttledGenerate = await getThrottledGenerateContent();
      const result = await throttledGenerate(this.model, prompt);
      const response = result.response;
      const text = response.text();

      // Track token usage
      const usage = response.usageMetadata;
      if (usage) {
        this.totalTokensUsed += usage.totalTokenCount || 0;
      }

      // Parse JSON response
      let jsonResponse: AIBatchResponse;
      try {
        // Extract JSON from markdown code blocks if present
        const jsonMatch = text.match(/```json\n?([\s\S]*?)\n?```/) || text.match(/\{[\s\S]*\}/);
        const jsonText = jsonMatch ? jsonMatch[1] || jsonMatch[0] : text;
        jsonResponse = JSON.parse(jsonText);
      } catch (parseError) {
        // Fallback: return empty analysis if parsing fails
        console.warn('Failed to parse AI response, returning empty analysis');
        jsonResponse = {
          analyses: sanitizedRequest.packages.map(pkg => ({
            package: pkg.name,
            version: pkg.version,
            falsePositivesFiltered: 0,
            newThreatsDetected: 0,
            insights: [],
            confidence: 0,
            tokensUsed: 0,
          })),
          totalTokensUsed: usage?.totalTokenCount || 0,
        };
      }

      // Cache the response
      this.setCachedResponse(cacheKey, jsonResponse);

      return jsonResponse;
    } catch (error: any) {
      // Handle API errors gracefully
      if (error.status === 429) {
        throw new Error('Rate limit exceeded. Please try again later.');
      } else if (error.status === 401) {
        throw new Error('Invalid API key. Please check your GOOGLE_AI_API_KEY.');
      } else if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
        throw new Error('Request timeout. The AI service took too long to respond.');
      } else {
        throw new Error(`AI analysis failed: ${error.message || 'Unknown error'}`);
      }
    }
  }

  /**
   * Clear the response cache
   */
  public clearCache(): void {
    cache.clear();
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): { size: number; keys: string[] } {
    return {
      size: cache.size,
      keys: Array.from(cache.keys()),
    };
  }
}

/**
 * Create a singleton Gemini client instance
 */
let clientInstance: GeminiClient | null = null;

export function getGeminiClient(apiKey?: string): GeminiClient {
  if (!clientInstance) {
    clientInstance = new GeminiClient(apiKey);
  }
  return clientInstance;
}

export function resetGeminiClient(): void {
  clientInstance = null;
}
