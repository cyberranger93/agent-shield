export interface ToolCallRisk {
  tool_name: string;
  arguments_provided: Record<string, unknown>;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  risks_detected: string[];
  recommendation: string;
}

const DANGEROUS_ARGUMENT_VALUES = [
  '../', '..\\', '/etc/', 'C:\\Windows', '.ssh', '.env', 'id_rsa',
  'passwd', 'shadow', 'token', 'secret', 'credential',
  'attacker.com', 'malicious.com', 'ngrok.io',
  'rm -rf', 'DROP TABLE', 'DELETE FROM', 'chmod 777',
];

const INJECTION_VALUE_PATTERNS = [
  'ignore previous', 'ignore all', 'new instruction', 'system override',
  'do not inform', 'exfiltrate', 'send to', 'forward to',
];

function stringifyValue(v: unknown): string {
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}

export function analyzeToolCall(toolName: string, args: Record<string, unknown>): ToolCallRisk {
  const risks: string[] = [];

  for (const [argName, argValue] of Object.entries(args)) {
    const strVal = stringifyValue(argValue).toLowerCase();

    for (const dangerous of DANGEROUS_ARGUMENT_VALUES) {
      if (strVal.includes(dangerous.toLowerCase())) {
        risks.push(`Argument "${argName}" contains suspicious value: "${dangerous}"`);
      }
    }

    for (const pattern of INJECTION_VALUE_PATTERNS) {
      if (strVal.includes(pattern)) {
        risks.push(`Argument "${argName}" contains injection pattern: "${pattern}" — possible prompt injection in tool call`);
      }
    }

    if (typeof argValue === 'string' && argValue.length > 10000) {
      risks.push(`Argument "${argName}" is unusually long (${argValue.length} chars) — potential data exfiltration via tool parameter`);
    }
  }

  const risk_level =
    risks.some((r) => r.includes('injection pattern') || r.includes('.ssh') || r.includes('attacker')) ? 'critical' :
    risks.some((r) => r.includes('suspicious')) ? 'high' :
    risks.length > 0 ? 'medium' : 'safe';

  return {
    tool_name: toolName,
    arguments_provided: args,
    risk_level,
    risks_detected: risks,
    recommendation: risks.length > 0
      ? `Tool call to "${toolName}" contains ${risks.length} risk indicator(s). Validate all arguments before executing. Consider requiring human approval for this tool call.`
      : `Tool call to "${toolName}" appears safe.`,
  };
}
