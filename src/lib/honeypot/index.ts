/**
 * Trap - Honeypot Security System
 * 
 * Main entry point for the Trap library.
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

// Trap definitions
export { honeypotTraps, HONEYPOT_TRAPS } from './traps';
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
import { honeypotTraps, HONEYPOT_TRAPS } from './traps';
import { getGeolocation } from './geolocation';
import { getWhoisInfo } from './whois';
import { blockIP, unblockIP, isIPBlocked, getBlockedIPs } from './blocker';

export default {
  collect: collectHoneypotData,
  traps: honeypotTraps,
  TRAPS: HONEYPOT_TRAPS,
  geo: getGeolocation,
  whois: getWhoisInfo,
  block: blockIP,
  unblock: unblockIP,
  isBlocked: isIPBlocked,
  getBlocked: getBlockedIPs,
};

