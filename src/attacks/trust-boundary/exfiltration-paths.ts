export interface ExfiltrationPath {
  id: string;
  name: string;
  vector: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  indicators: string[];
  mitigation: string;
}

export const EXFILTRATION_PATHS: ExfiltrationPath[] = [
  {
    id: 'EX-PATH-001',
    name: 'HTTP Tool Exfiltration',
    vector: 'tool-call',
    severity: 'critical',
    description: 'Agent instructed to call HTTP tool with conversation data encoded in query parameters.',
    indicators: ['fetch(', 'http.get(', 'GET /collect?', 'data=encodeURIComponent', 'exfil'],
    mitigation: 'Blocklist external URLs in HTTP tools. Only allow GET requests to pre-approved domains.',
  },
  {
    id: 'EX-PATH-002',
    name: 'Email Exfiltration',
    vector: 'email-tool',
    severity: 'critical',
    description: 'Agent sends conversation history or system prompt via email tool to attacker-controlled address.',
    indicators: ['send_email', 'to: attacker', 'subject: exfil', 'body: system prompt'],
    mitigation: 'Require human approval for all agent-sent emails. Restrict recipient domains.',
  },
  {
    id: 'EX-PATH-003',
    name: 'Memory/Storage Write Exfiltration',
    vector: 'storage-tool',
    severity: 'high',
    description: 'Agent writes sensitive data to a publicly accessible location (shared drive, public S3 bucket, pastebin).',
    indicators: ['write_file', 'upload', 'pastebin', 'public', 's3.amazonaws.com'],
    mitigation: 'Audit storage tool permissions. Ensure agent cannot write to publicly accessible storage.',
  },
  {
    id: 'EX-PATH-004',
    name: 'DNS Exfiltration',
    vector: 'network',
    severity: 'high',
    description: 'Sensitive data encoded and sent via DNS lookup — bypasses HTTP-level monitoring.',
    indicators: ['nslookup', 'dig', 'dns', '.attacker.', 'encoded.subdomain'],
    mitigation: 'Block DNS tool access. Monitor for unusual subdomain patterns in network logs.',
  },
  {
    id: 'EX-PATH-005',
    name: 'Webhook Exfiltration',
    vector: 'webhook-tool',
    severity: 'critical',
    description: 'Agent posts data to attacker-controlled webhook endpoint disguised as a legitimate integration.',
    indicators: ['webhook', 'POST to', 'notify.', 'hook.', 'discord.com/api/webhooks', 'hooks.slack.com'],
    mitigation: 'Validate webhook URLs against allowlist. Log all webhook invocations with full payload for audit.',
  },
];

export function detectExfiltrationPath(toolCallOrContent: string): ExfiltrationPath[] {
  const lower = toolCallOrContent.toLowerCase();
  return EXFILTRATION_PATHS.filter((path) =>
    path.indicators.some((ind) => lower.includes(ind.toLowerCase()))
  );
}
