/**
 * Trap - Honeypot Security System
 * 
 * Advanced honeypot for Next.js applications with:
 * - 195+ trap patterns
 * - 500+ attack detection patterns
 * - Real-time Telegram alerts
 * - Interactive threat management
 * - Browser fingerprinting
 * - Media capture capabilities
 */

// Core modules
export { collectHoneypotData } from './collector';
export type { 
  HoneypotData, 
  AttackType, 
  Severity, 
  BrowserFingerprint, 
  GPSLocation, 
  CapturedCredentials,
  GeoData 
} from './collector';

// Attack detection
export { detectAttackType, extractHeaders } from './detector';
export type { DetectionResult } from './detector';

// Trap definitions
export { honeypotTraps, matchTrap, generateFakeEnv, TRAP_PATTERNS } from './traps';
export type { HoneypotTrap } from './traps';

// Geolocation
export { getGeolocation } from './geolocation';
export type { GeoData as GeoLocationData } from './geolocation';

// WHOIS
export { getWhoisInfo, getAbuseContact, formatWhoisData } from './whois';
export type { WhoisData } from './whois';

// IP Blocking
export { 
  blockIP, 
  unblockIP, 
  isIPBlocked, 
  getBlockedIPs, 
  getBlockInfo 
} from './blocker';
export type { BlockedIP, BlockDuration } from './blocker';

// Default export for convenience
import { collectHoneypotData } from './collector';
import { detectAttackType, extractHeaders } from './detector';
import { honeypotTraps, matchTrap, generateFakeEnv, TRAP_PATTERNS } from './traps';
import { getGeolocation } from './geolocation';
import { getWhoisInfo } from './whois';
import { blockIP, unblockIP, isIPBlocked, getBlockedIPs } from './blocker';

const Trap = {
  // Data collection
  collect: collectHoneypotData,
  
  // Attack detection
  detect: detectAttackType,
  extractHeaders,
  
  // Trap matching
  traps: honeypotTraps,
  matchTrap,
  generateFakeEnv,
  PATTERNS: TRAP_PATTERNS,
  
  // Geolocation
  geo: getGeolocation,
  
  // WHOIS
  whois: getWhoisInfo,
  
  // IP blocking
  block: blockIP,
  unblock: unblockIP,
  isBlocked: isIPBlocked,
  getBlocked: getBlockedIPs,
};

export default Trap;
