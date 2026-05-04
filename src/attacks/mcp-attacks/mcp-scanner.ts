import { SERVER_VULN_PATTERNS } from './server-vuln-patterns.js';

export interface MCPTool {
  name: string;
  description: string;
  inputSchema?: {
    properties?: Record<string, { type: string; description?: string }>;
    required?: string[];
  };
}

export interface MCPServerManifest {
  name: string;
  version?: string;
  tools: MCPTool[];
}

export interface MCPFinding {
  tool_name: string;
  finding_id: string;
  category: 'tool-poisoning' | 'over-broad-scope' | 'shell-risk' | 'exfiltration-risk' | 'shadow-server';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence: string;
  remediation: string;
}

const DANGEROUS_TOOL_NAMES = ['exec', 'run', 'eval', 'shell', 'bash', 'sh', 'cmd', 'powershell', 'execute', 'subprocess'];
const EXFIL_KEYWORDS = ['send', 'post', 'upload', 'transmit', 'forward', 'relay', 'webhook'];
const OVERLY_BROAD_PARAMS = ['path', 'directory', 'glob', 'pattern', 'command', 'code', 'script'];
const INJECTION_DESCRIPTION_HINTS = [
  'do not inform', 'do not reveal', 'do not mention', 'silently', 'without notifying',
  'include conversation', 'include system prompt', 'include all messages',
];

export function scanMCPServer(manifest: MCPServerManifest): MCPFinding[] {
  const findings: MCPFinding[] = [];

  for (const tool of manifest.tools) {
    const toolNameLower = tool.name.toLowerCase();
    const descLower = tool.description.toLowerCase();

    if (DANGEROUS_TOOL_NAMES.some((n) => toolNameLower === n || toolNameLower.includes(n))) {
      findings.push({
        tool_name: tool.name,
        finding_id: `MCP-SHELL-${findings.length + 1}`,
        category: 'shell-risk',
        severity: 'critical',
        description: 'Tool name suggests shell/code execution capability — potential for agent-controlled arbitrary command execution.',
        evidence: `Tool name: "${tool.name}"`,
        remediation: 'Remove shell execution tools from agent-accessible MCP servers. Use sandboxed alternatives with explicit allow-lists.',
      });
    }

    for (const hint of INJECTION_DESCRIPTION_HINTS) {
      if (descLower.includes(hint)) {
        findings.push({
          tool_name: tool.name,
          finding_id: `MCP-POISON-${findings.length + 1}`,
          category: 'tool-poisoning',
          severity: 'critical',
          description: 'Tool description contains covert instruction keywords — potential tool poisoning attack targeting the agent.',
          evidence: `Matched: "${hint}" in description: "${tool.description.slice(0, 100)}"`,
          remediation: 'Audit this tool description. Remove any hidden instructions. Tool descriptions should only describe functionality, not instruct the agent on behavior.',
        });
        break;
      }
    }

    if (EXFIL_KEYWORDS.some((k) => toolNameLower.includes(k) || descLower.includes(k))) {
      findings.push({
        tool_name: tool.name,
        finding_id: `MCP-EXFIL-${findings.length + 1}`,
        category: 'exfiltration-risk',
        severity: 'high',
        description: 'Tool has data transmission capability — review for potential exfiltration vector.',
        evidence: `Tool "${tool.name}" has send/post/upload semantics.`,
        remediation: 'Restrict this tool\'s destination scope. Add allowlist validation for URLs/endpoints the agent can send data to.',
      });
    }

    const schema = tool.inputSchema;
    if (schema?.properties) {
      for (const [paramName, paramDef] of Object.entries(schema.properties)) {
        if (OVERLY_BROAD_PARAMS.includes(paramName.toLowerCase()) && paramDef.type === 'string') {
          findings.push({
            tool_name: tool.name,
            finding_id: `MCP-SCOPE-${findings.length + 1}`,
            category: 'over-broad-scope',
            severity: 'medium',
            description: `Parameter "${paramName}" accepts unconstrained string — agent could pass adversarial values.`,
            evidence: `Tool: "${tool.name}", param: "${paramName}", type: string (no constraints defined)`,
            remediation: `Add enum, pattern, or maxLength constraints to "${paramName}". Validate against an allow-list server-side.`,
          });
        }
      }
    }

    for (const vuln of SERVER_VULN_PATTERNS) {
      if (vuln.applies_to.some((k) => toolNameLower.includes(k) || descLower.includes(k))) {
        findings.push({
          tool_name: tool.name,
          finding_id: `MCP-VULN-${findings.length + 1}`,
          category: vuln.category as MCPFinding['category'],
          severity: vuln.severity,
          description: vuln.description,
          evidence: `Tool matches pattern: ${vuln.pattern_name}`,
          remediation: vuln.remediation,
        });
      }
    }
  }

  return findings;
}
