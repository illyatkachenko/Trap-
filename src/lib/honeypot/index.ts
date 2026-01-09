/**
 * Trap - Honeypot Security System
 * 
 * Advanced honeypot for Next.js applications with:
 * - 195+ trap patterns
 * - 500+ attack detection patterns
 * - Real-time Telegram/Slack/Discord alerts
 * - Interactive threat management
 * - Browser fingerprinting
 * - Media capture capabilities
 * - Auto-blocking rules
 * - Threat intelligence integration
 * - Country blocking
 * - API key monitoring
 * - Behavior analysis (bot detection)
 * - Attack statistics dashboard
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

// Auto-block rules
export {
  processAttack,
  getRules,
  setRules,
  addRule,
  removeRule,
  enableRule,
  getAttackStats,
  DEFAULT_RULES,
} from './autoblock';
export type { AutoBlockRule, BlockCondition, BlockAction, AttackEvent } from './autoblock';

// Notifications (Telegram, Slack, Discord, Email, Webhook)
export {
  sendAlert,
  getTrackerPixelUrl,
  generateTrackerPixelHtml,
} from './notifications';
export type { NotificationConfig, AlertData } from './notifications';

// Behavior analysis (bot detection)
export {
  getBehaviorTrackingScript,
  analyzeBehaviorData,
} from './behavior';
export type { BehaviorAnalysis, MouseData, TypingData } from './behavior';

// API Key monitoring
export {
  isFakeKey,
  trackFakeKeyUsage,
  trackKeyUsage,
  createStripeMonitor,
  createResendMonitor,
  createKeyMonitor,
  getKeyUsageStats,
  getFakeKeyAttempts,
} from './key-monitor';

// Threat intelligence
export {
  checkAbuseIPDB,
  checkVirusTotal,
  checkGreyNoise,
  checkAllSources,
  reportToAbuseIPDB,
  autoReportAttack,
  ABUSEIPDB_CATEGORIES,
} from './threat-intel';
export type { ThreatIntelResult, ThreatSource } from './threat-intel';

// Country blocking
export {
  getConfig as getCountryConfig,
  setConfig as setCountryConfig,
  checkCountry,
  addCountry,
  removeCountry,
  blockHighRiskCountries,
  allowOnlyCountries,
  allowOnlyEU,
  generateCloudflareRules,
  generateNginxRules,
  generateIPTablesRules,
  getCountryStats,
  HIGH_RISK_COUNTRIES,
  COUNTRY_NAMES,
} from './country-block';
export type { CountryBlockConfig, CountryCheckResult } from './country-block';

// Statistics & Dashboard
export {
  recordAttack,
  getStats,
  getAttack,
  getAttacksByIP,
  getAttacksByType,
  getRecentAttacks,
  exportToCSV,
  exportToJSON,
  generateDashboardHTML,
} from './statistics';
export type { AttackRecord, DashboardStats } from './statistics';

// Default export for convenience
import { collectHoneypotData } from './collector';
import { detectAttackType, extractHeaders } from './detector';
import { honeypotTraps, matchTrap, generateFakeEnv, TRAP_PATTERNS } from './traps';
import { getGeolocation } from './geolocation';
import { getWhoisInfo } from './whois';
import { blockIP, unblockIP, isIPBlocked, getBlockedIPs } from './blocker';
import { processAttack, getRules, DEFAULT_RULES } from './autoblock';
import { sendAlert } from './notifications';
import { getBehaviorTrackingScript, analyzeBehaviorData } from './behavior';
import { isFakeKey, createStripeMonitor, createResendMonitor } from './key-monitor';
import { checkAllSources, autoReportAttack } from './threat-intel';
import { checkCountry, blockHighRiskCountries } from './country-block';
import { getStats, recordAttack, generateDashboardHTML } from './statistics';

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
  
  // Auto-block
  processAttack,
  getRules,
  DEFAULT_RULES,
  
  // Notifications
  alert: sendAlert,
  
  // Behavior analysis
  getBehaviorScript: getBehaviorTrackingScript,
  analyzeBehavior: analyzeBehaviorData,
  
  // Key monitoring
  isFakeKey,
  monitorStripe: createStripeMonitor,
  monitorResend: createResendMonitor,
  
  // Threat intelligence
  checkThreatIntel: checkAllSources,
  reportAttack: autoReportAttack,
  
  // Country blocking
  checkCountry,
  blockHighRiskCountries,
  
  // Statistics
  stats: getStats,
  record: recordAttack,
  dashboard: generateDashboardHTML,
};

export default Trap;
