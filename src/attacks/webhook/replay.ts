export interface ReplayCheckResult {
  is_replay: boolean;
  reason: string;
  timestamp_age_seconds: number | null;
  risk_level: 'safe' | 'medium' | 'high' | 'critical';
}

const SEEN_NONCES = new Set<string>();
const MAX_AGE_SECONDS = 300;

export function checkReplayAttack(
  timestamp: string | number | undefined,
  nonce: string | undefined,
  maxAgeSeconds: number = MAX_AGE_SECONDS
): ReplayCheckResult {
  if (!timestamp) {
    return { is_replay: true, reason: 'No timestamp in webhook — replay attack cannot be detected.', timestamp_age_seconds: null, risk_level: 'high' };
  }

  const ts = typeof timestamp === 'string' ? parseInt(timestamp, 10) : timestamp;
  const nowSeconds = Math.floor(Date.now() / 1000);
  const ageSeconds = nowSeconds - ts;

  if (ageSeconds > maxAgeSeconds) {
    return {
      is_replay: true,
      reason: `Webhook timestamp is ${ageSeconds}s old (max allowed: ${maxAgeSeconds}s) — likely replay attack.`,
      timestamp_age_seconds: ageSeconds,
      risk_level: 'critical',
    };
  }

  if (ageSeconds < 0) {
    return {
      is_replay: true,
      reason: `Webhook timestamp is in the future (${Math.abs(ageSeconds)}s ahead) — clock skew or forged timestamp.`,
      timestamp_age_seconds: ageSeconds,
      risk_level: 'high',
    };
  }

  if (nonce) {
    if (SEEN_NONCES.has(nonce)) {
      return {
        is_replay: true,
        reason: `Nonce "${nonce}" has been seen before — replay attack detected.`,
        timestamp_age_seconds: ageSeconds,
        risk_level: 'critical',
      };
    }
    SEEN_NONCES.add(nonce);
    if (SEEN_NONCES.size > 10000) {
      const firstKey = SEEN_NONCES.values().next().value;
      if (firstKey) SEEN_NONCES.delete(firstKey);
    }
  }

  return {
    is_replay: false,
    reason: `Webhook is fresh (${ageSeconds}s old) and nonce is unique.`,
    timestamp_age_seconds: ageSeconds,
    risk_level: 'safe',
  };
}
