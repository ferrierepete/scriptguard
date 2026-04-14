/** ScriptGuard — Simplified deobfuscation (Layer 3, decode-only, NO code execution) */

import { parse } from 'acorn';
import type { DeobfuscationResult } from '../types/index.js';

/**
 * Deobfuscate a script by decoding obvious encoding layers.
 * This is a DECODE-ONLY approach — NO code execution.
 *
 * @param scriptContent - The obfuscated JavaScript code
 * @param maxIterations - Maximum decode iterations (default: 2)
 * @returns Deobfuscation result with deobfuscated code and metadata
 */
export function deobfuscateScript(
  scriptContent: string,
  maxIterations: number = 2
): DeobfuscationResult {
  // Skip large scripts (>1MB) to prevent memory issues
  if (scriptContent.length > 1_000_000) {
    return {
      deobfuscated: scriptContent,
      iterations: 0,
      techniques: [],
      success: false,
    };
  }

  let current = scriptContent;
  const techniques: string[] = [];
  let iterations = 0;

  for (let i = 0; i < maxIterations; i++) {
    const previous = current;
    const iterationTechniques: string[] = [];

    // Layer 1: Base64 decoding
    current = decodeBase64Layers(current, iterationTechniques);

    // Layer 2: Hex escape decoding
    current = decodeHexEscapes(current, iterationTechniques);

    // Layer 3: Unicode escape decoding
    current = decodeUnicodeEscapes(current, iterationTechniques);

    // Check if we made progress
    if (current === previous) {
      break;
    }

    techniques.push(...iterationTechniques);
    iterations++;

    // Safety: Stop if script becomes too large (exponential unpacking prevention)
    if (current.length > scriptContent.length * 10) {
      // Script grew too much — potential unpacking bomb
      return {
        deobfuscated: scriptContent, // Return original
        iterations: 0,
        techniques: [],
        success: false,
      };
    }
  }

  // Validate that deobfuscated code is still valid JavaScript
  if (iterations > 0) {
    try {
      parse(current, {
        ecmaVersion: 'latest',
        sourceType: 'script',
      });

      // Deobfuscated successfully and is valid JS
      return {
        deobfuscated: current,
        iterations,
        techniques,
        success: true,
      };
    } catch {
      // Deobfuscation produced invalid syntax — return original
      return {
        deobfuscated: scriptContent,
        iterations: 0,
        techniques: [],
        success: false,
      };
    }
  }

  // No deobfuscation occurred
  return {
    deobfuscated: scriptContent,
    iterations: 0,
    techniques: [],
    success: false,
  };
}

/**
 * Decode base64-encoded strings in the script.
 * Detects: atob(...), Buffer.from(..., 'base64'), base64 -d patterns
 *
 * Only decodes OBVIOUS patterns (no nested expressions) to avoid false positives.
 */
function decodeBase64Layers(script: string, techniques: string[]): string {
  let result = script;

  // Pattern 1: atob('base64string')
  const atobPattern = /atob\s*\(\s*(['"`])([A-Za-z0-9+/=]+)\1\s*\)/g;
  result = result.replace(atobPattern, (match, quote, base64) => {
    try {
      const decoded = Buffer.from(base64, 'base64').toString('utf-8');
      // Only replace if decoded looks like valid text (no control characters)
      if (/^[\x20-\x7E\s]*$/.test(decoded)) {
        techniques.push('base64-atob');
        return JSON.stringify(decoded); // Return as quoted string
      }
    } catch {
      // Invalid base64 — return original
    }
    return match;
  });

  // Pattern 2: Buffer.from('base64string', 'base64')
  const bufferPattern = /Buffer\.from\s*\(\s*(['"`])([A-Za-z0-9+/=]+)\1\s*,\s*['"`]base64['"`]\s*\)/g;
  result = result.replace(bufferPattern, (match, quote, base64) => {
    try {
      const decoded = Buffer.from(base64, 'base64').toString('utf-8');
      if (/^[\x20-\x7E\s]*$/.test(decoded)) {
        techniques.push('base64-buffer');
        return JSON.stringify(decoded);
      }
    } catch {
      // Invalid base64
    }
    return match;
  });

  // Pattern 3: .toString('base64') chains (reverse)
  // This is more complex and may produce false positives, so be conservative
  const toStringPattern = /\.toString\s*\(\s*['"`]base64['"`]\s*\)/g;
  // Don't auto-replace these — they're harder to detect safely

  return result;
}

/**
 * Decode hexadecimal escape sequences: \xNN
 */
function decodeHexEscapes(script: string, techniques: string[]): string {
  let result = script;
  let hasDecoded = false;

  // Match \xNN patterns (where NN are hex digits)
  const hexPattern = /\\x([0-9a-fA-F]{2})/g;

  result = result.replace(hexPattern, (match, hex) => {
    const charCode = parseInt(hex, 16);
    const char = String.fromCharCode(charCode);
    hasDecoded = true;
    return char;
  });

  if (hasDecoded) {
    techniques.push('hex-escape');
  }

  return result;
}

/**
 * Decode Unicode escape sequences: \uNNNN
 */
function decodeUnicodeEscapes(script: string, techniques: string[]): string {
  let result = script;
  let hasDecoded = false;

  // Match \uNNNN patterns (where NNNN are hex digits)
  const unicodePattern = /\\u([0-9a-fA-F]{4})/g;

  result = result.replace(unicodePattern, (match, hex) => {
    const charCode = parseInt(hex, 16);
    const char = String.fromCharCode(charCode);
    hasDecoded = true;
    return char;
  });

  if (hasDecoded) {
    techniques.push('unicode-escape');
  }

  return result;
}
