/** ScriptGuard — AST-based pattern detection (Layer 2) */

import { parse } from 'acorn';
import * as walk from 'acorn-walk';
import type { ASTFinding } from '../types/index.js';

/**
 * Dangerous objects that we want to track access to
 */
const DANGEROUS_OBJECTS = new Set([
  'process',
  'fs',
  'child_process',
  'net',
  'http',
  'https',
  'url',
  'path',
  'os',
  'crypto',
  'vm',
  'cluster',
]);

/**
 * Analyze script content using AST to detect structural patterns
 * that regex cannot see (dynamic require, computed eval, etc.)
 *
 * @param scriptContent - The JavaScript code to analyze
 * @returns Array of AST findings (empty if parse fails or no patterns found)
 */
export function analyzeScriptAST(
  scriptContent: string
): ASTFinding[] {
  // Skip large scripts (>1MB) to prevent memory issues
  if (scriptContent.length > 1_000_000) {
    return [];
  }

  let ast: any;

  try {
    ast = parse(scriptContent, {
      ecmaVersion: 'latest',
      sourceType: 'script',
    });
  } catch (error) {
    // Malformed JavaScript — return empty array (graceful degradation)
    return [];
  }

  const findings: ASTFinding[] = [];

  // Walk the AST and detect patterns
  walk.simple(ast, {
    // Detect: require(variable), require(computed), require('child_' + 'process')
    CallExpression(node: any) {
      const callee = node.callee;

      // Pattern 1: Dynamic require()
      if (callee.type === 'Identifier' && callee.name === 'require') {
        if (node.arguments.length > 0) {
          const arg = node.arguments[0];

          // Flag if argument is NOT a literal string
          if (!isLiteral(arg)) {
            findings.push({
              pattern: 'ast-dynamic-require',
              description: 'Dynamic require() with non-literal argument — may load arbitrary modules',
              riskLevel: 'high',
              nodeType: 'CallExpression',
              match: extractMatch(scriptContent, node),
            });
          }
        }
      }

      // Pattern 2: Computed eval() or Function()
      if (
        (callee.type === 'Identifier' && (callee.name === 'eval' || callee.name === 'Function')) ||
        (callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          (callee.property.name === 'eval' || callee.property.name === 'Function'))
      ) {
        if (node.arguments.length > 0) {
          const arg = node.arguments[0];

          // Flag if argument is NOT a literal string
          if (!isLiteral(arg)) {
            findings.push({
              pattern: 'ast-computed-eval',
              description: 'Computed eval() or Function() — may execute arbitrary code',
              riskLevel: 'critical',
              nodeType: 'CallExpression',
              match: extractMatch(scriptContent, node),
            });
          }
        }
      }
    },

    // Pattern 3: Computed property access on dangerous objects
    // Example: process.env[computed], fs['read' + 'File']
    MemberExpression(node: any) {
      if (node.computed) {
        // Check if object is dangerous
        const objectName = getObjectName(node.object);
        if (objectName && DANGEROUS_OBJECTS.has(objectName)) {
          // Flag if property is computed (not a literal)
          if (!isLiteral(node.property)) {
            findings.push({
              pattern: 'ast-computed-property',
              description: `Computed property access on ${objectName} — may bypass keyword detection`,
              riskLevel: 'high',
              nodeType: 'MemberExpression',
              match: extractMatch(scriptContent, node),
            });
          }
        }
      }
    },

    // Pattern 4: String concatenation building dangerous keywords
    // Example: 'child_' + 'process', 'eval' + variable
    BinaryExpression(node: any) {
      if (node.operator === '+') {
        const built = tryResolveBinaryExpression(node);
        if (built && containsDangerousKeyword(built)) {
          findings.push({
            pattern: 'ast-string-building',
            description: 'String concatenation building dangerous keywords — possible obfuscation',
            riskLevel: 'medium',
            nodeType: 'BinaryExpression',
            match: extractMatch(scriptContent, node),
          });
        }
      }
    },
  });

  return findings;
}

/**
 * Check if an AST node is a literal (string, number, boolean, null)
 */
function isLiteral(node: any): boolean {
  if (!node) return false;

  if (node.type === 'Literal') {
    return true;
  }

  // Template literals with no expressions are literals
  if (node.type === 'TemplateLiteral') {
    return node.expressions.length === 0;
  }

  return false;
}

/**
 * Get the name of an object from a MemberExpression or Identifier
 */
function getObjectName(node: any): string | null {
  if (!node) return null;

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'MemberExpression') {
    return getObjectName(node.object);
  }

  return null;
}

/**
 * Try to resolve a binary expression to a string
 * Returns null if resolution fails
 */
function tryResolveBinaryExpression(node: any): string | null {
  if (!node) return null;

  // If it's a literal, return its value
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  // If it's a binary expression, try to resolve both sides
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = tryResolveBinaryExpression(node.left);
    const right = tryResolveBinaryExpression(node.right);

    if (left !== null && right !== null) {
      return left + right;
    }
  }

  return null;
}

/**
 * Check if a string contains dangerous keywords
 */
function containsDangerousKeyword(str: string): boolean {
  const lower = str.toLowerCase();
  const dangerousKeywords = [
    'eval',
    'function',
    'require',
    'exec',
    'spawn',
    'child_process',
    'process.env',
    'fs.',
    'http.',
    'net.',
  ];

  for (const keyword of dangerousKeywords) {
    if (lower.includes(keyword)) {
      return true;
    }
  }

  return false;
}

/**
 * Extract the source code for a given AST node
 */
function extractMatch(scriptContent: string, node: any): string {
  if (!node || !node.loc) {
    return '';
  }

  try {
    const lines = scriptContent.split('\n');
    const startLine = node.loc.start.line - 1; // 0-indexed
    const endLine = node.loc.end.line - 1;
    const startCol = node.loc.start.column;
    const endCol = node.loc.end.column;

    if (startLine === endLine) {
      // Single line
      const line = lines[startLine];
      return line.substring(startCol, endCol);
    } else {
      // Multi-line
      let result = lines[startLine].substring(startCol);
      for (let i = startLine + 1; i < endLine; i++) {
        result += '\n' + lines[i];
      }
      result += '\n' + lines[endLine].substring(0, endCol);
      return result;
    }
  } catch {
    return '';
  }
}
