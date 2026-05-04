import { createHmac, timingSafeEqual } from 'node:crypto';

export interface WebhookVerificationResult {
  valid: boolean;
  reason: string;
  risk_level: 'safe' | 'medium' | 'high' | 'critical';
}

export function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string,
  secret: string,
  algorithm: string = 'sha256',
  headerPrefix: string = 'sha256='
): WebhookVerificationResult {
  if (!signature) {
    return { valid: false, reason: 'No signature header present — webhook forgery risk.', risk_level: 'critical' };
  }

  if (!secret) {
    return { valid: false, reason: 'No webhook secret configured — cannot verify authenticity.', risk_level: 'critical' };
  }

  const expectedSig = createHmac(algorithm, secret)
    .update(typeof payload === 'string' ? Buffer.from(payload) : payload)
    .digest('hex');

  const expectedFull = `${headerPrefix}${expectedSig}`;
  const receivedFull = signature.startsWith(headerPrefix) ? signature : `${headerPrefix}${signature}`;

  const expected = Buffer.from(expectedFull);
  const received = Buffer.from(receivedFull);

  if (expected.length !== received.length) {
    return { valid: false, reason: 'Signature length mismatch — likely forged.', risk_level: 'critical' };
  }

  const isValid = timingSafeEqual(expected, received);

  return {
    valid: isValid,
    reason: isValid ? 'Signature verified.' : 'Signature mismatch — webhook may be forged.',
    risk_level: isValid ? 'safe' : 'critical',
  };
}

export function detectWebhookForgeryIndicators(headers: Record<string, string>): string[] {
  const risks: string[] = [];
  if (!headers['x-hub-signature-256'] && !headers['x-signature'] && !headers['x-webhook-signature']) {
    risks.push('No standard signature header present');
  }
  if (!headers['content-type']?.includes('application/json')) {
    risks.push('Content-Type is not application/json — unexpected for most webhooks');
  }
  if (headers['x-forwarded-for']) {
    risks.push(`Request forwarded through proxy: ${headers['x-forwarded-for']} — source IP may be spoofed`);
  }
  return risks;
}
