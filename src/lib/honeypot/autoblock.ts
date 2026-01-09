/**
 * Trap - Auto-Block Rules Engine
 * 
 * Automatically blocks IPs based on configurable rules:
 * - Rate limiting (N attacks in M minutes)
 * - Severity thresholds
 * - Attack type patterns
 * - Country-based blocking
 */

import { blockIP, isIPBlocked, BlockDuration } from './blocker';
import type { AttackType, Severity } from './collector';

// ============================================
// Types
// ============================================

export interface AutoBlockRule {
  id: string;
  name: string;
  enabled: boolean;
  conditions: BlockCondition[];
  action: BlockAction;
  cooldown: number; // Seconds before rule can trigger again for same IP
}

export interface BlockCondition {
  type: 'attack_count' | 'severity' | 'attack_type' | 'country' | 'user_agent' | 'path_pattern';
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains' | 'matches';
  value: string | number | string[];
  timeWindow?: number; // Seconds (for attack_count)
}

export interface BlockAction {
  type: 'block' | 'alert' | 'challenge';
  duration: BlockDuration;
  notifyTelegram: boolean;
  notifySlack?: boolean;
  notifyDiscord?: boolean;
}

export interface AttackEvent {
  ip: string;
  timestamp: number;
  attackType: AttackType;
  severity: Severity;
  path: string;
  userAgent: string;
  country?: string;
}

// ============================================
// In-memory attack tracking
// ============================================

const attackHistory: Map<string, AttackEvent[]> = new Map();
const ruleCooldowns: Map<string, number> = new Map(); // ruleId:ip -> lastTriggered

// Cleanup old events every 5 minutes
setInterval(() => {
  const now = Date.now();
  const maxAge = 3600000; // 1 hour
  
  attackHistory.forEach((events, ip) => {
    const filtered = events.filter(e => now - e.timestamp < maxAge);
    if (filtered.length === 0) {
      attackHistory.delete(ip);
    } else {
      attackHistory.set(ip, filtered);
    }
  });
}, 300000);

// ============================================
// Default Rules
// ============================================

export const DEFAULT_RULES: AutoBlockRule[] = [
  {
    id: 'critical-instant',
    name: 'Block CRITICAL attacks instantly',
    enabled: true,
    conditions: [
      { type: 'severity', operator: 'eq', value: 'CRITICAL' }
    ],
    action: {
      type: 'block',
      duration: '24h',
      notifyTelegram: true,
    },
    cooldown: 0,
  },
  {
    id: 'high-3-in-5min',
    name: 'Block after 3 HIGH attacks in 5 minutes',
    enabled: true,
    conditions: [
      { type: 'severity', operator: 'eq', value: 'HIGH' },
      { type: 'attack_count', operator: 'gte', value: 3, timeWindow: 300 }
    ],
    action: {
      type: 'block',
      duration: '1h',
      notifyTelegram: true,
    },
    cooldown: 300,
  },
  {
    id: 'brute-force-10-in-1min',
    name: 'Block brute force (10 attempts in 1 minute)',
    enabled: true,
    conditions: [
      { type: 'attack_type', operator: 'eq', value: 'BRUTE_FORCE' },
      { type: 'attack_count', operator: 'gte', value: 10, timeWindow: 60 }
    ],
    action: {
      type: 'block',
      duration: '1h',
      notifyTelegram: true,
    },
    cooldown: 60,
  },
  {
    id: 'scanner-detection',
    name: 'Block automated scanners',
    enabled: true,
    conditions: [
      { type: 'user_agent', operator: 'matches', value: 'sqlmap|nikto|nmap|masscan|acunetix|nessus|burp|zap' }
    ],
    action: {
      type: 'block',
      duration: 'permanent',
      notifyTelegram: true,
    },
    cooldown: 0,
  },
  {
    id: 'webshell-instant',
    name: 'Block webshell attempts instantly',
    enabled: true,
    conditions: [
      { type: 'attack_type', operator: 'eq', value: 'WEBSHELL_UPLOAD' }
    ],
    action: {
      type: 'block',
      duration: 'permanent',
      notifyTelegram: true,
    },
    cooldown: 0,
  },
  {
    id: 'any-20-in-10min',
    name: 'Block after 20 attacks of any type in 10 minutes',
    enabled: true,
    conditions: [
      { type: 'attack_count', operator: 'gte', value: 20, timeWindow: 600 }
    ],
    action: {
      type: 'block',
      duration: '1h',
      notifyTelegram: true,
    },
    cooldown: 600,
  },
];

// Active rules (can be modified at runtime)
let activeRules: AutoBlockRule[] = [...DEFAULT_RULES];

// ============================================
// Rule Management
// ============================================

export function getRules(): AutoBlockRule[] {
  return activeRules;
}

export function setRules(rules: AutoBlockRule[]): void {
  activeRules = rules;
}

export function addRule(rule: AutoBlockRule): void {
  activeRules.push(rule);
}

export function removeRule(ruleId: string): boolean {
  const index = activeRules.findIndex(r => r.id === ruleId);
  if (index >= 0) {
    activeRules.splice(index, 1);
    return true;
  }
  return false;
}

export function enableRule(ruleId: string, enabled: boolean): boolean {
  const rule = activeRules.find(r => r.id === ruleId);
  if (rule) {
    rule.enabled = enabled;
    return true;
  }
  return false;
}

// ============================================
// Attack Processing
// ============================================

export async function processAttack(event: AttackEvent): Promise<{
  blocked: boolean;
  triggeredRules: string[];
  reason?: string;
}> {
  // Skip if already blocked
  if (await isIPBlocked(event.ip)) {
    return { blocked: true, triggeredRules: [], reason: 'Already blocked' };
  }

  // Add to history
  const history = attackHistory.get(event.ip) || [];
  history.push(event);
  attackHistory.set(event.ip, history);

  // Check rules
  const triggeredRules: string[] = [];
  
  for (const rule of activeRules) {
    if (!rule.enabled) continue;
    
    // Check cooldown
    const cooldownKey = `${rule.id}:${event.ip}`;
    const lastTriggered = ruleCooldowns.get(cooldownKey) || 0;
    if (rule.cooldown > 0 && Date.now() - lastTriggered < rule.cooldown * 1000) {
      continue;
    }
    
    // Check conditions
    if (checkConditions(rule.conditions, event, history)) {
      triggeredRules.push(rule.id);
      
      // Execute action
      if (rule.action.type === 'block') {
        await blockIP(
          event.ip,
          rule.action.duration,
          `Auto-blocked by rule: ${rule.name}`,
          'AutoBlock',
          event.attackType,
          event.severity
        );
        
        // Set cooldown
        ruleCooldowns.set(cooldownKey, Date.now());
        
        return {
          blocked: true,
          triggeredRules,
          reason: rule.name,
        };
      }
    }
  }

  return { blocked: false, triggeredRules };
}

function checkConditions(conditions: BlockCondition[], event: AttackEvent, history: AttackEvent[]): boolean {
  return conditions.every(condition => checkCondition(condition, event, history));
}

function checkCondition(condition: BlockCondition, event: AttackEvent, history: AttackEvent[]): boolean {
  switch (condition.type) {
    case 'severity':
      return compareValue(event.severity, condition.operator, condition.value);
    
    case 'attack_type':
      return compareValue(event.attackType, condition.operator, condition.value);
    
    case 'country':
      return compareValue(event.country || '', condition.operator, condition.value);
    
    case 'user_agent':
      if (condition.operator === 'matches' && typeof condition.value === 'string') {
        const regex = new RegExp(condition.value, 'i');
        return regex.test(event.userAgent);
      }
      return compareValue(event.userAgent, condition.operator, condition.value);
    
    case 'path_pattern':
      if (condition.operator === 'matches' && typeof condition.value === 'string') {
        const regex = new RegExp(condition.value, 'i');
        return regex.test(event.path);
      }
      return compareValue(event.path, condition.operator, condition.value);
    
    case 'attack_count':
      const timeWindow = condition.timeWindow || 300; // Default 5 minutes
      const now = Date.now();
      const recentAttacks = history.filter(e => now - e.timestamp < timeWindow * 1000);
      return compareValue(recentAttacks.length, condition.operator, condition.value);
    
    default:
      return false;
  }
}

function compareValue(actual: any, operator: string, expected: any): boolean {
  switch (operator) {
    case 'eq':
      return actual === expected;
    case 'ne':
      return actual !== expected;
    case 'gt':
      return actual > expected;
    case 'lt':
      return actual < expected;
    case 'gte':
      return actual >= expected;
    case 'lte':
      return actual <= expected;
    case 'contains':
      if (Array.isArray(expected)) {
        return expected.includes(actual);
      }
      return String(actual).includes(String(expected));
    case 'matches':
      const regex = new RegExp(String(expected), 'i');
      return regex.test(String(actual));
    default:
      return false;
  }
}

// ============================================
// Statistics
// ============================================

export function getAttackStats(ip?: string): {
  totalAttacks: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  recentAttacks: AttackEvent[];
} {
  let events: AttackEvent[] = [];
  
  if (ip) {
    events = attackHistory.get(ip) || [];
  } else {
    attackHistory.forEach(ipEvents => {
      events = events.concat(ipEvents);
    });
  }
  
  const byType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  
  events.forEach(e => {
    byType[e.attackType] = (byType[e.attackType] || 0) + 1;
    bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
  });
  
  return {
    totalAttacks: events.length,
    byType,
    bySeverity,
    recentAttacks: events.slice(-50),
  };
}

export default {
  processAttack,
  getRules,
  setRules,
  addRule,
  removeRule,
  enableRule,
  getAttackStats,
  DEFAULT_RULES,
};

