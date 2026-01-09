/**
 * Trap - API Key Monitoring
 * 
 * Monitor for unauthorized usage of API keys (Resend, Stripe, etc.)
 * Detects when stolen "fake" keys are used and alerts immediately.
 * Also monitors real key usage for anomalies.
 */

import { sendAlert } from './notifications';

// ============================================
// Types
// ============================================

export interface KeyUsageEvent {
  keyType: 'stripe' | 'resend' | 'aws' | 'telegram' | 'custom';
  keyPrefix: string; // First 10-15 chars for identification
  action: string;
  timestamp: string;
  ip?: string;
  userAgent?: string;
  success: boolean;
  error?: string;
  metadata?: Record<string, any>;
}

export interface KeyMonitorConfig {
  enabled: boolean;
  alertOnFailure: boolean;
  alertOnUnusualActivity: boolean;
  maxRequestsPerMinute: number;
  maxRequestsPerHour: number;
  allowedIPs?: string[];
  blockedIPs?: string[];
}

export interface FakeKeyConfig {
  keyType: string;
  keyPattern: string; // Regex pattern to match fake keys
  alertMessage: string;
}

// ============================================
// In-memory tracking
// ============================================

const keyUsageHistory: Map<string, KeyUsageEvent[]> = new Map();
const fakeKeyAttempts: Map<string, { count: number; lastAttempt: number; ips: Set<string> }> = new Map();

// Cleanup old events every 10 minutes
setInterval(() => {
  const now = Date.now();
  const maxAge = 3600000; // 1 hour
  
  keyUsageHistory.forEach((events, key) => {
    const filtered = events.filter(e => now - new Date(e.timestamp).getTime() < maxAge);
    if (filtered.length === 0) {
      keyUsageHistory.delete(key);
    } else {
      keyUsageHistory.set(key, filtered);
    }
  });
}, 600000);

// ============================================
// Fake Key Patterns (for honeypot)
// ============================================

const FAKE_KEY_PATTERNS: FakeKeyConfig[] = [
  {
    keyType: 'stripe',
    keyPattern: 'sk_live_.*FAKE.*HONEYPOT',
    alertMessage: 'Someone tried to use a FAKE Stripe key from honeypot!',
  },
  {
    keyType: 'resend',
    keyPattern: 're_.*FAKE.*HONEYPOT',
    alertMessage: 'Someone tried to use a FAKE Resend key from honeypot!',
  },
  {
    keyType: 'aws',
    keyPattern: 'AKIA.*FAKE',
    alertMessage: 'Someone tried to use a FAKE AWS key from honeypot!',
  },
  {
    keyType: 'telegram',
    keyPattern: '\\d+:.*FAKE.*',
    alertMessage: 'Someone tried to use a FAKE Telegram bot token from honeypot!',
  },
];

// ============================================
// Check if key is fake (from honeypot)
// ============================================

export function isFakeKey(key: string): { isFake: boolean; keyType?: string; message?: string } {
  for (const pattern of FAKE_KEY_PATTERNS) {
    const regex = new RegExp(pattern.keyPattern, 'i');
    if (regex.test(key)) {
      return {
        isFake: true,
        keyType: pattern.keyType,
        message: pattern.alertMessage,
      };
    }
  }
  return { isFake: false };
}

// ============================================
// Track fake key usage attempt
// ============================================

export async function trackFakeKeyUsage(
  key: string,
  ip: string,
  userAgent: string,
  service: string,
  action: string
): Promise<void> {
  const keyPrefix = key.slice(0, 20);
  const existing = fakeKeyAttempts.get(keyPrefix) || { count: 0, lastAttempt: 0, ips: new Set() };
  
  existing.count++;
  existing.lastAttempt = Date.now();
  existing.ips.add(ip);
  fakeKeyAttempts.set(keyPrefix, existing);

  // Send critical alert
  await sendAlert({
    ip,
    attackType: 'DATA_EXFILTRATION',
    severity: 'CRITICAL',
    path: `/${service}/${action}`,
    details: `🚨 FAKE API KEY USED! Key: ${keyPrefix}... Service: ${service}. This key was from honeypot!`,
    timestamp: new Date().toISOString(),
    userAgent,
    blocked: false,
  });

  console.error(`[Trap] 🚨 FAKE KEY USAGE DETECTED! IP: ${ip}, Key: ${keyPrefix}..., Service: ${service}`);
}

// ============================================
// Monitor real key usage
// ============================================

export async function trackKeyUsage(event: KeyUsageEvent): Promise<{
  anomaly: boolean;
  reason?: string;
}> {
  const key = event.keyPrefix;
  const history = keyUsageHistory.get(key) || [];
  history.push(event);
  keyUsageHistory.set(key, history);

  // Check for anomalies
  const anomalies = detectAnomalies(key, history, event);
  
  if (anomalies.length > 0) {
    await sendAlert({
      ip: event.ip || 'unknown',
      attackType: 'DATA_EXFILTRATION',
      severity: 'HIGH',
      path: `/${event.keyType}/${event.action}`,
      details: `⚠️ Unusual API key activity: ${anomalies.join(', ')}`,
      timestamp: event.timestamp,
      userAgent: event.userAgent,
      blocked: false,
    });

    return { anomaly: true, reason: anomalies.join(', ') };
  }

  return { anomaly: false };
}

function detectAnomalies(key: string, history: KeyUsageEvent[], current: KeyUsageEvent): string[] {
  const anomalies: string[] = [];
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  const oneHourAgo = now - 3600000;

  // Get recent events
  const lastMinute = history.filter(e => new Date(e.timestamp).getTime() > oneMinuteAgo);
  const lastHour = history.filter(e => new Date(e.timestamp).getTime() > oneHourAgo);

  // Rate limit check
  if (lastMinute.length > 100) {
    anomalies.push(`High rate: ${lastMinute.length} requests/min`);
  }
  if (lastHour.length > 1000) {
    anomalies.push(`High volume: ${lastHour.length} requests/hour`);
  }

  // Multiple IPs using same key
  const uniqueIPs = new Set(lastHour.filter(e => e.ip).map(e => e.ip));
  if (uniqueIPs.size > 5) {
    anomalies.push(`Multiple IPs: ${uniqueIPs.size} different IPs`);
  }

  // Unusual time (if configured)
  const hour = new Date().getHours();
  if (hour >= 2 && hour <= 5) {
    // Late night activity might be suspicious
    if (lastMinute.length > 10) {
      anomalies.push('Unusual late-night activity');
    }
  }

  // High failure rate
  const failures = lastHour.filter(e => !e.success);
  if (failures.length > 10 && failures.length / lastHour.length > 0.5) {
    anomalies.push(`High failure rate: ${Math.round(failures.length / lastHour.length * 100)}%`);
  }

  return anomalies;
}

// ============================================
// Stripe Webhook Monitor
// ============================================

export function createStripeMonitor(stripeSecretKey: string) {
  const keyPrefix = stripeSecretKey.slice(0, 15);
  
  return {
    async trackRequest(action: string, ip?: string, userAgent?: string, success: boolean = true, error?: string) {
      // Check if it's a fake key
      const fakeCheck = isFakeKey(stripeSecretKey);
      if (fakeCheck.isFake) {
        await trackFakeKeyUsage(stripeSecretKey, ip || 'unknown', userAgent || 'unknown', 'stripe', action);
        return;
      }

      await trackKeyUsage({
        keyType: 'stripe',
        keyPrefix,
        action,
        timestamp: new Date().toISOString(),
        ip,
        userAgent,
        success,
        error,
      });
    },
  };
}

// ============================================
// Resend Monitor
// ============================================

export function createResendMonitor(resendApiKey: string) {
  const keyPrefix = resendApiKey.slice(0, 15);
  
  return {
    async trackEmail(to: string, subject: string, ip?: string, userAgent?: string, success: boolean = true, error?: string) {
      // Check if it's a fake key
      const fakeCheck = isFakeKey(resendApiKey);
      if (fakeCheck.isFake) {
        await trackFakeKeyUsage(resendApiKey, ip || 'unknown', userAgent || 'unknown', 'resend', 'send_email');
        return;
      }

      await trackKeyUsage({
        keyType: 'resend',
        keyPrefix,
        action: 'send_email',
        timestamp: new Date().toISOString(),
        ip,
        userAgent,
        success,
        error,
        metadata: {
          to: to.includes('@') ? to.split('@')[1] : 'hidden', // Only domain for privacy
          subjectLength: subject.length,
        },
      });
    },
  };
}

// ============================================
// Generic Key Monitor
// ============================================

export function createKeyMonitor(keyType: string, apiKey: string) {
  const keyPrefix = apiKey.slice(0, 15);
  
  return {
    async track(action: string, ip?: string, userAgent?: string, success: boolean = true, error?: string, metadata?: Record<string, any>) {
      // Check if it's a fake key
      const fakeCheck = isFakeKey(apiKey);
      if (fakeCheck.isFake) {
        await trackFakeKeyUsage(apiKey, ip || 'unknown', userAgent || 'unknown', keyType, action);
        return;
      }

      await trackKeyUsage({
        keyType: keyType as any,
        keyPrefix,
        action,
        timestamp: new Date().toISOString(),
        ip,
        userAgent,
        success,
        error,
        metadata,
      });
    },
  };
}

// ============================================
// Get usage statistics
// ============================================

export function getKeyUsageStats(keyPrefix?: string): {
  totalRequests: number;
  successRate: number;
  uniqueIPs: number;
  recentEvents: KeyUsageEvent[];
  fakeKeyAttempts: number;
} {
  let events: KeyUsageEvent[] = [];
  
  if (keyPrefix) {
    events = keyUsageHistory.get(keyPrefix) || [];
  } else {
    keyUsageHistory.forEach(keyEvents => {
      events = events.concat(keyEvents);
    });
  }

  const successful = events.filter(e => e.success);
  const uniqueIPs = new Set(events.filter(e => e.ip).map(e => e.ip));

  let totalFakeAttempts = 0;
  fakeKeyAttempts.forEach(attempt => {
    totalFakeAttempts += attempt.count;
  });

  return {
    totalRequests: events.length,
    successRate: events.length > 0 ? successful.length / events.length : 1,
    uniqueIPs: uniqueIPs.size,
    recentEvents: events.slice(-20),
    fakeKeyAttempts: totalFakeAttempts,
  };
}

// ============================================
// Get fake key attempt details
// ============================================

export function getFakeKeyAttempts(): Array<{
  keyPrefix: string;
  count: number;
  lastAttempt: string;
  ips: string[];
}> {
  const results: Array<{
    keyPrefix: string;
    count: number;
    lastAttempt: string;
    ips: string[];
  }> = [];

  fakeKeyAttempts.forEach((data, keyPrefix) => {
    results.push({
      keyPrefix,
      count: data.count,
      lastAttempt: new Date(data.lastAttempt).toISOString(),
      ips: Array.from(data.ips),
    });
  });

  return results.sort((a, b) => b.count - a.count);
}

export default {
  isFakeKey,
  trackFakeKeyUsage,
  trackKeyUsage,
  createStripeMonitor,
  createResendMonitor,
  createKeyMonitor,
  getKeyUsageStats,
  getFakeKeyAttempts,
};

