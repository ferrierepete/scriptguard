/** ScriptGuard — Pattern rules for detecting malicious lifecycle scripts */

import type { PatternRule } from '../types/index.js';

export const PATTERN_RULES: PatternRule[] = [
  // === NETWORK — data exfiltration vectors ===
  {
    name: 'curl-pipe',
    pattern: /curl\s+[^|]*\|\s*(?:sh|bash|sudo|zsh)/,
    riskLevel: 'critical',
    description: 'Downloads and executes remote code via curl pipe',
    category: 'network',
  },
  {
    name: 'wget-pipe',
    pattern: /wget\s+.*\|\s*(?:sh|bash|sudo|zsh)/,
    riskLevel: 'critical',
    description: 'Downloads and executes remote code via wget pipe',
    category: 'network',
  },
  {
    name: 'curl-silent',
    pattern: /curl\s+.*-[sS]\b/,
    riskLevel: 'high',
    description: 'Silent HTTP request — common in data exfiltration',
    category: 'network',
  },
  {
    name: 'curl-post',
    pattern: /curl\s+.*-[dX]\s+(?:POST|PUT|PATCH)/,
    riskLevel: 'high',
    description: 'HTTP POST/PUT request — may send data externally',
    category: 'network',
  },
  {
    name: 'http-request',
    pattern: /(?:https?:\/\/[^\s'"]+|fetch\s*\(|request\s*\(|http\.request|http\.get|axios|got\()/,
    riskLevel: 'medium',
    description: 'Outbound HTTP request detected',
    category: 'network',
  },
  {
    name: 'dns-lookup',
    pattern: /(?:nslookup|dig|host\s+\S+\.\S+|dns\.resolve)/,
    riskLevel: 'medium',
    description: 'DNS lookup — can be used for DNS-based data exfiltration',
    category: 'network',
  },
  {
    name: 'geo-ip-lookup',
    pattern: /(?:ipgeo|geolocation|ipify|ipinfo|ip-api|freegeoip|ipgeolocation)\.(?:io|com|net|org)|\/ipgeo\?|geoip/,
    riskLevel: 'critical',
    description: 'IP geolocation lookup — targeting based on location',
    category: 'network',
  },

  // === EXECUTION — arbitrary code execution ===
  {
    name: 'eval-usage',
    pattern: /(?:^|\s|;|&&|\|\|)(?:eval|Function)\s*[\($]/,
    riskLevel: 'high',
    description: 'eval() or Function() constructor — arbitrary code execution',
    category: 'execution',
  },
  {
    name: 'child-process',
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(/,
    riskLevel: 'medium',
    description: 'Spawns child process — can execute arbitrary commands',
    category: 'execution',
  },
  {
    name: 'shell-exec',
    pattern: /(?:sh\s+-c|bash\s+-c|zsh\s+-c|\/bin\/sh|\/bin\/bash|\/bin\/zsh)/,
    riskLevel: 'high',
    description: 'Direct shell execution',
    category: 'execution',
  },
  {
    name: 'node-eval',
    pattern: /node\s+-e\s+/,
    riskLevel: 'high',
    description: 'Evaluates Node.js code from command line',
    category: 'execution',
  },
  {
    name: 'require-resolve',
    pattern: /require\s*\(\s*[^'"]*\+/,
    riskLevel: 'medium',
    description: 'Dynamic require with string concatenation',
    category: 'execution',
  },

  // === FILESYSTEM — sensitive file access ===
  {
    name: 'ssh-access',
    pattern: /(?:~\/\.ssh|\/\.ssh|id_rsa|id_ed25519|id_ecdsa)/,
    riskLevel: 'critical',
    description: 'Accesses SSH keys — credential theft risk',
    category: 'filesystem',
  },
  {
    name: 'aws-creds',
    pattern: /(?:~\/\.aws|\/\.aws|AWS_|aws_access_key|aws_secret_key)/,
    riskLevel: 'critical',
    description: 'Accesses AWS credentials — cloud account takeover risk',
    category: 'filesystem',
  },
  {
    name: 'env-file',
    pattern: /\.env(?:\.local|\.production|\.staging)?/,
    riskLevel: 'high',
    description: 'Reads .env files — may expose secrets',
    category: 'filesystem',
  },
  {
    name: 'passwd-shadow',
    pattern: /\/etc\/(?:passwd|shadow|sudoers|hosts)/,
    riskLevel: 'critical',
    description: 'Reads system credential files',
    category: 'filesystem',
  },
  {
    name: 'tmp-write',
    pattern: /(?:\/tmp\/|os\.tmpdir|tempdir|writeFileSync|writeFile).*\.sh/,
    riskLevel: 'medium',
    description: 'Writes executable to temp directory',
    category: 'filesystem',
  },
  {
    name: 'chmod-exec',
    pattern: /chmod\s+\+x/,
    riskLevel: 'medium',
    description: 'Makes a file executable',
    category: 'filesystem',
  },
  {
    name: 'fs-write',
    pattern: /fs\.(writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rename|renameSync|rmdir|rmdirSync)\s*\(/,
    riskLevel: 'high',
    description: 'Writes or modifies files on the filesystem',
    category: 'filesystem',
  },
  {
    name: 'home-dir-access',
    pattern: /homedir\s*\(\)/,
    riskLevel: 'high',
    description: 'Accesses the user home directory path',
    category: 'filesystem',
  },

  // === EXFILTRATION — stealing data ===
  {
    name: 'env-exfil',
    pattern: /(?:process\.env|export|printenv|env\s)/,
    riskLevel: 'high',
    description: 'Reads environment variables — may contain secrets',
    category: 'exfiltration',
  },
  {
    name: 'clipboard-access',
    pattern: /(?:pbcopy|xclip|xsel|clipboard)/,
    riskLevel: 'high',
    description: 'Accesses system clipboard — can steal copied data',
    category: 'exfiltration',
  },
  {
    name: 'keychain-access',
    pattern: /(?:security\s+find|keychain|osascript.*keychain)/,
    riskLevel: 'critical',
    description: 'Accesses macOS Keychain or credential store',
    category: 'exfiltration',
  },
  {
    name: 'network-interfaces',
    pattern: /networkInterfaces\s*\(\)/,
    riskLevel: 'medium',
    description: 'Enumerates network interfaces — information gathering',
    category: 'exfiltration',
  },

  // === OBFUSCATION — hiding malicious intent ===
  {
    name: 'base64-exec',
    pattern: /(?:base64\s+-d|atob|Buffer\.from\s*\([^)]*,\s*['"]base64['"]\))\s*[;|&&\n].*(?:eval|exec|sh|bash)/,
    riskLevel: 'critical',
    description: 'Base64 decode + execute — classic obfuscation technique',
    category: 'obfuscation',
  },
  {
    name: 'hex-encode',
    pattern: /\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}/,
    riskLevel: 'high',
    description: 'Hex-encoded strings — likely hiding payload',
    category: 'obfuscation',
  },
  {
    name: 'unicode-escape',
    pattern: /\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/,
    riskLevel: 'medium',
    description: 'Unicode-escaped strings — potential obfuscation',
    category: 'obfuscation',
  },

  // === CRYPTO — mining or ransomware ===
  {
    name: 'crypto-miner',
    pattern: /(?:xmrig|minerd|cpuminer|cryptonight|stratum\+tcp)/,
    riskLevel: 'critical',
    description: 'Cryptocurrency mining detected',
    category: 'crypto',
  },
  {
    name: 'reverse-shell',
    pattern: /(?:nc\s+-|ncat|socat|\/dev\/tcp|bash\s+-i\s+>&)/,
    riskLevel: 'critical',
    description: 'Reverse shell pattern — full system takeover',
    category: 'execution',
  },
];
