export interface ServerVulnPattern {
  pattern_name: string;
  applies_to: string[];
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  remediation: string;
}

export const SERVER_VULN_PATTERNS: ServerVulnPattern[] = [
  {
    pattern_name: 'Filesystem Traversal Risk',
    applies_to: ['read_file', 'readfile', 'read-file', 'get_file', 'fetch_file', 'load_file'],
    category: 'over-broad-scope',
    severity: 'high',
    description: 'File read tool may allow path traversal — agent could read sensitive files (SSH keys, .env files, credentials).',
    remediation: 'Restrict file read to an explicit allowlist directory. Validate paths server-side to prevent ../../../etc/passwd traversal.',
  },
  {
    pattern_name: 'Filesystem Write Risk',
    applies_to: ['write_file', 'writefile', 'write-file', 'save_file', 'create_file', 'update_file'],
    category: 'over-broad-scope',
    severity: 'critical',
    description: 'File write tool allows agent to modify arbitrary files — potential for persistence, credential theft, or data destruction.',
    remediation: 'Restrict write operations to a sandboxed directory. Require explicit user approval for writes outside designated folders.',
  },
  {
    pattern_name: 'Network Request Tool',
    applies_to: ['fetch', 'http', 'request', 'get_url', 'browse', 'navigate'],
    category: 'exfiltration-risk',
    severity: 'high',
    description: 'General HTTP tool with unrestricted URL — agent could be instructed to exfiltrate data to any endpoint.',
    remediation: 'Implement URL allowlist. Block requests to non-HTTPS endpoints, private IPs (169.254.x.x, 10.x.x.x), and known exfil domains.',
  },
  {
    pattern_name: 'Email Send Tool',
    applies_to: ['send_email', 'sendemail', 'email', 'send_message', 'mail'],
    category: 'exfiltration-risk',
    severity: 'critical',
    description: 'Email tool with agent-controlled recipient — could be hijacked via prompt injection to send sensitive data externally.',
    remediation: 'Require human approval before sending emails. Restrict recipients to a pre-approved list. Log all emails sent by agents.',
  },
  {
    pattern_name: 'Calendar Modification',
    applies_to: ['create_event', 'update_event', 'delete_event', 'schedule'],
    category: 'exfiltration-risk',
    severity: 'medium',
    description: 'Calendar modification tool could be used by injected instructions to leak meeting data or add unauthorized participants.',
    remediation: 'Require user confirmation for calendar modifications. Log all agent-initiated calendar changes.',
  },
  {
    pattern_name: 'Code Execution',
    applies_to: ['run_code', 'execute_code', 'eval_code', 'python', 'javascript', 'node', 'repl'],
    category: 'shell-risk',
    severity: 'critical',
    description: 'Code execution tool allows agent to run arbitrary code — maximum risk vector for jailbreak-via-code.',
    remediation: 'Sandbox code execution in isolated containers (Docker/gVisor). Disable network access from the sandbox. Timeout all executions.',
  },
];
