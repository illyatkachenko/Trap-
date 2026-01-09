/**
 * Trap - Threat Intelligence Integration
 * 
 * Integrates with external threat intelligence services:
 * - AbuseIPDB
 * - VirusTotal
 * - Shodan
 * - GreyNoise
 */

// ============================================
// Types
// ============================================

export interface ThreatIntelResult {
  ip: string;
  isMalicious: boolean;
  confidenceScore: number; // 0-100
  sources: ThreatSource[];
  categories: string[];
  lastReported?: string;
  totalReports?: number;
  countryCode?: string;
  isp?: string;
  domain?: string;
  isProxy?: boolean;
  isVpn?: boolean;
  isTor?: boolean;
  isHosting?: boolean;
}

export interface ThreatSource {
  name: string;
  score: number;
  categories: string[];
  lastSeen?: string;
  details?: string;
}

export interface AbuseIPDBResult {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string;
  usageType: string;
  isp: string;
  domain: string;
  hostnames: string[];
  isTor: boolean;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string;
}

export interface VirusTotalResult {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

// ============================================
// Configuration
// ============================================

const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
const GREYNOISE_API_KEY = process.env.GREYNOISE_API_KEY;

// ============================================
// AbuseIPDB
// ============================================

export async function checkAbuseIPDB(ip: string): Promise<ThreatSource | null> {
  if (!ABUSEIPDB_API_KEY) {
    console.warn('[Trap] AbuseIPDB API key not configured');
    return null;
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`, {
      headers: {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      console.error('[Trap] AbuseIPDB error:', response.status);
      return null;
    }

    const data = await response.json();
    const result: AbuseIPDBResult = data.data;

    return {
      name: 'AbuseIPDB',
      score: result.abuseConfidenceScore,
      categories: getCategoriesFromAbuseIPDB(result),
      lastSeen: result.lastReportedAt,
      details: `${result.totalReports} reports from ${result.numDistinctUsers} users. ISP: ${result.isp}`,
    };
  } catch (error) {
    console.error('[Trap] AbuseIPDB error:', error);
    return null;
  }
}

function getCategoriesFromAbuseIPDB(result: AbuseIPDBResult): string[] {
  const categories: string[] = [];
  if (result.isTor) categories.push('Tor Exit Node');
  if (result.usageType === 'Data Center/Web Hosting/Transit') categories.push('Hosting');
  if (result.abuseConfidenceScore > 50) categories.push('Known Attacker');
  if (result.totalReports > 10) categories.push('Frequently Reported');
  return categories;
}

// ============================================
// Report to AbuseIPDB
// ============================================

export async function reportToAbuseIPDB(
  ip: string,
  categories: number[],
  comment: string
): Promise<boolean> {
  if (!ABUSEIPDB_API_KEY) {
    console.warn('[Trap] AbuseIPDB API key not configured');
    return false;
  }

  try {
    const response = await fetch('https://api.abuseipdb.com/api/v2/report', {
      method: 'POST',
      headers: {
        'Key': ABUSEIPDB_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        ip,
        categories: categories.join(','),
        comment: comment.slice(0, 1024), // Max 1024 chars
      }),
    });

    if (!response.ok) {
      console.error('[Trap] AbuseIPDB report error:', response.status);
      return false;
    }

    console.log(`[Trap] Reported ${ip} to AbuseIPDB`);
    return true;
  } catch (error) {
    console.error('[Trap] AbuseIPDB report error:', error);
    return false;
  }
}

// AbuseIPDB category codes
export const ABUSEIPDB_CATEGORIES = {
  DNS_COMPROMISE: 1,
  DNS_POISONING: 2,
  FRAUD_ORDERS: 3,
  DDOS_ATTACK: 4,
  FTP_BRUTE_FORCE: 5,
  PING_OF_DEATH: 6,
  PHISHING: 7,
  FRAUD_VOIP: 8,
  OPEN_PROXY: 9,
  WEB_SPAM: 10,
  EMAIL_SPAM: 11,
  BLOG_SPAM: 12,
  VPN_IP: 13,
  PORT_SCAN: 14,
  HACKING: 15,
  SQL_INJECTION: 16,
  SPOOFING: 17,
  BRUTE_FORCE: 18,
  BAD_WEB_BOT: 19,
  EXPLOITED_HOST: 20,
  WEB_APP_ATTACK: 21,
  SSH: 22,
  IOT_TARGETED: 23,
};

// ============================================
// VirusTotal
// ============================================

export async function checkVirusTotal(ip: string): Promise<ThreatSource | null> {
  if (!VIRUSTOTAL_API_KEY) {
    console.warn('[Trap] VirusTotal API key not configured');
    return null;
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
      },
    });

    if (!response.ok) {
      console.error('[Trap] VirusTotal error:', response.status);
      return null;
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats as VirusTotalResult;
    const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
    const maliciousScore = total > 0 ? Math.round((stats.malicious / total) * 100) : 0;

    const categories: string[] = [];
    if (stats.malicious > 0) categories.push(`${stats.malicious} engines flagged as malicious`);
    if (stats.suspicious > 0) categories.push(`${stats.suspicious} engines flagged as suspicious`);

    return {
      name: 'VirusTotal',
      score: maliciousScore,
      categories,
      details: `Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}, Harmless: ${stats.harmless}`,
    };
  } catch (error) {
    console.error('[Trap] VirusTotal error:', error);
    return null;
  }
}

// ============================================
// GreyNoise
// ============================================

export async function checkGreyNoise(ip: string): Promise<ThreatSource | null> {
  if (!GREYNOISE_API_KEY) {
    // GreyNoise has a free community API
    try {
      const response = await fetch(`https://api.greynoise.io/v3/community/${ip}`);
      
      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      
      const categories: string[] = [];
      if (data.noise) categories.push('Internet Scanner');
      if (data.riot) categories.push('Known Benign Service');
      if (data.classification === 'malicious') categories.push('Malicious');
      
      return {
        name: 'GreyNoise',
        score: data.classification === 'malicious' ? 80 : data.noise ? 50 : 0,
        categories,
        lastSeen: data.last_seen,
        details: data.name || data.message,
      };
    } catch (error) {
      return null;
    }
  }

  try {
    const response = await fetch(`https://api.greynoise.io/v2/noise/context/${ip}`, {
      headers: {
        'key': GREYNOISE_API_KEY,
      },
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    
    const categories: string[] = [];
    if (data.seen) categories.push('Seen Scanning');
    if (data.classification === 'malicious') categories.push('Malicious');
    if (data.classification === 'benign') categories.push('Benign');
    if (data.bot) categories.push('Known Bot');
    if (data.vpn) categories.push('VPN');
    
    return {
      name: 'GreyNoise',
      score: data.classification === 'malicious' ? 80 : data.seen ? 40 : 0,
      categories,
      lastSeen: data.last_seen,
      details: `${data.actor || 'Unknown actor'}. Tags: ${(data.tags || []).join(', ')}`,
    };
  } catch (error) {
    console.error('[Trap] GreyNoise error:', error);
    return null;
  }
}

// ============================================
// Combined Check
// ============================================

export async function checkAllSources(ip: string): Promise<ThreatIntelResult> {
  const sources: ThreatSource[] = [];
  const categories: Set<string> = new Set();

  // Run all checks in parallel
  const [abuseIPDB, virusTotal, greyNoise] = await Promise.all([
    checkAbuseIPDB(ip),
    checkVirusTotal(ip),
    checkGreyNoise(ip),
  ]);

  if (abuseIPDB) {
    sources.push(abuseIPDB);
    abuseIPDB.categories.forEach(c => categories.add(c));
  }

  if (virusTotal) {
    sources.push(virusTotal);
    virusTotal.categories.forEach(c => categories.add(c));
  }

  if (greyNoise) {
    sources.push(greyNoise);
    greyNoise.categories.forEach(c => categories.add(c));
  }

  // Calculate overall score
  const scores = sources.map(s => s.score).filter(s => s > 0);
  const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
  
  // Use max score if any source is very confident
  const confidenceScore = maxScore > 70 ? maxScore : avgScore;

  return {
    ip,
    isMalicious: confidenceScore > 50,
    confidenceScore,
    sources,
    categories: Array.from(categories),
    isProxy: categories.has('Open Proxy') || categories.has('VPN'),
    isVpn: categories.has('VPN'),
    isTor: categories.has('Tor Exit Node'),
    isHosting: categories.has('Hosting'),
  };
}

// ============================================
// Auto-report attack to AbuseIPDB
// ============================================

export async function autoReportAttack(
  ip: string,
  attackType: string,
  path: string,
  details: string
): Promise<boolean> {
  // Map attack types to AbuseIPDB categories
  const categoryMap: Record<string, number[]> = {
    SQL_INJECTION: [ABUSEIPDB_CATEGORIES.SQL_INJECTION, ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK],
    XSS: [ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK],
    BRUTE_FORCE: [ABUSEIPDB_CATEGORIES.BRUTE_FORCE],
    PATH_TRAVERSAL: [ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK, ABUSEIPDB_CATEGORIES.HACKING],
    COMMAND_INJECTION: [ABUSEIPDB_CATEGORIES.HACKING, ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK],
    WEBSHELL_UPLOAD: [ABUSEIPDB_CATEGORIES.HACKING, ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK],
    ENV_DISCLOSURE: [ABUSEIPDB_CATEGORIES.HACKING],
    SCANNER: [ABUSEIPDB_CATEGORIES.PORT_SCAN, ABUSEIPDB_CATEGORIES.BAD_WEB_BOT],
    CRYPTOMINER: [ABUSEIPDB_CATEGORIES.EXPLOITED_HOST],
    MALWARE_INJECTION: [ABUSEIPDB_CATEGORIES.HACKING],
  };

  const categories = categoryMap[attackType] || [ABUSEIPDB_CATEGORIES.WEB_APP_ATTACK];
  const comment = `Trap Honeypot: ${attackType} attack detected. Path: ${path}. ${details}`.slice(0, 1024);

  return reportToAbuseIPDB(ip, categories, comment);
}

export default {
  checkAbuseIPDB,
  checkVirusTotal,
  checkGreyNoise,
  checkAllSources,
  reportToAbuseIPDB,
  autoReportAttack,
  ABUSEIPDB_CATEGORIES,
};

