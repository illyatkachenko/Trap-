/**
 * Trap - Country Blocking Module
 * 
 * Block or allow traffic based on country codes.
 * Supports both blacklist and whitelist modes.
 */

import { getGeolocation } from './geolocation';

// ============================================
// Types
// ============================================

export type BlockMode = 'blacklist' | 'whitelist';

export interface CountryBlockConfig {
  enabled: boolean;
  mode: BlockMode;
  countries: string[]; // ISO 3166-1 alpha-2 codes
  allowedPaths?: string[]; // Paths that bypass country blocking
  customMessage?: string;
}

export interface CountryCheckResult {
  allowed: boolean;
  country?: string;
  countryCode?: string;
  reason?: string;
}

// ============================================
// Default Configuration
// ============================================

let config: CountryBlockConfig = {
  enabled: false,
  mode: 'blacklist',
  countries: [],
  allowedPaths: ['/api/health', '/api/status'],
};

// ============================================
// High-risk countries (commonly used for attacks)
// ============================================

export const HIGH_RISK_COUNTRIES = [
  'CN', // China
  'RU', // Russia
  'KP', // North Korea
  'IR', // Iran
  'SY', // Syria
];

export const COMMON_VPN_COUNTRIES = [
  'PA', // Panama
  'VG', // British Virgin Islands
  'SC', // Seychelles
];

// ============================================
// Country names for display
// ============================================

export const COUNTRY_NAMES: Record<string, string> = {
  AF: 'Afghanistan', AL: 'Albania', DZ: 'Algeria', AD: 'Andorra', AO: 'Angola',
  AR: 'Argentina', AM: 'Armenia', AU: 'Australia', AT: 'Austria', AZ: 'Azerbaijan',
  BH: 'Bahrain', BD: 'Bangladesh', BY: 'Belarus', BE: 'Belgium', BZ: 'Belize',
  BJ: 'Benin', BT: 'Bhutan', BO: 'Bolivia', BA: 'Bosnia', BW: 'Botswana',
  BR: 'Brazil', BN: 'Brunei', BG: 'Bulgaria', BF: 'Burkina Faso', BI: 'Burundi',
  KH: 'Cambodia', CM: 'Cameroon', CA: 'Canada', CF: 'Central African Republic',
  TD: 'Chad', CL: 'Chile', CN: 'China', CO: 'Colombia', CG: 'Congo',
  CR: 'Costa Rica', HR: 'Croatia', CU: 'Cuba', CY: 'Cyprus', CZ: 'Czech Republic',
  DK: 'Denmark', DJ: 'Djibouti', DO: 'Dominican Republic', EC: 'Ecuador',
  EG: 'Egypt', SV: 'El Salvador', EE: 'Estonia', ET: 'Ethiopia', FI: 'Finland',
  FR: 'France', GA: 'Gabon', GM: 'Gambia', GE: 'Georgia', DE: 'Germany',
  GH: 'Ghana', GR: 'Greece', GT: 'Guatemala', GN: 'Guinea', HT: 'Haiti',
  HN: 'Honduras', HK: 'Hong Kong', HU: 'Hungary', IS: 'Iceland', IN: 'India',
  ID: 'Indonesia', IR: 'Iran', IQ: 'Iraq', IE: 'Ireland', IL: 'Israel',
  IT: 'Italy', JM: 'Jamaica', JP: 'Japan', JO: 'Jordan', KZ: 'Kazakhstan',
  KE: 'Kenya', KP: 'North Korea', KR: 'South Korea', KW: 'Kuwait', KG: 'Kyrgyzstan',
  LA: 'Laos', LV: 'Latvia', LB: 'Lebanon', LY: 'Libya', LT: 'Lithuania',
  LU: 'Luxembourg', MK: 'North Macedonia', MG: 'Madagascar', MY: 'Malaysia',
  MV: 'Maldives', ML: 'Mali', MT: 'Malta', MX: 'Mexico', MD: 'Moldova',
  MC: 'Monaco', MN: 'Mongolia', ME: 'Montenegro', MA: 'Morocco', MZ: 'Mozambique',
  MM: 'Myanmar', NA: 'Namibia', NP: 'Nepal', NL: 'Netherlands', NZ: 'New Zealand',
  NI: 'Nicaragua', NE: 'Niger', NG: 'Nigeria', NO: 'Norway', OM: 'Oman',
  PK: 'Pakistan', PA: 'Panama', PY: 'Paraguay', PE: 'Peru', PH: 'Philippines',
  PL: 'Poland', PT: 'Portugal', QA: 'Qatar', RO: 'Romania', RU: 'Russia',
  RW: 'Rwanda', SA: 'Saudi Arabia', SN: 'Senegal', RS: 'Serbia', SG: 'Singapore',
  SK: 'Slovakia', SI: 'Slovenia', SO: 'Somalia', ZA: 'South Africa', ES: 'Spain',
  LK: 'Sri Lanka', SD: 'Sudan', SE: 'Sweden', CH: 'Switzerland', SY: 'Syria',
  TW: 'Taiwan', TJ: 'Tajikistan', TZ: 'Tanzania', TH: 'Thailand', TN: 'Tunisia',
  TR: 'Turkey', TM: 'Turkmenistan', UG: 'Uganda', UA: 'Ukraine', AE: 'UAE',
  GB: 'United Kingdom', US: 'United States', UY: 'Uruguay', UZ: 'Uzbekistan',
  VE: 'Venezuela', VN: 'Vietnam', YE: 'Yemen', ZM: 'Zambia', ZW: 'Zimbabwe',
};

// ============================================
// Configuration Management
// ============================================

export function getConfig(): CountryBlockConfig {
  return { ...config };
}

export function setConfig(newConfig: Partial<CountryBlockConfig>): void {
  config = { ...config, ...newConfig };
}

export function enableCountryBlocking(enabled: boolean): void {
  config.enabled = enabled;
}

export function setMode(mode: BlockMode): void {
  config.mode = mode;
}

export function addCountry(countryCode: string): void {
  const code = countryCode.toUpperCase();
  if (!config.countries.includes(code)) {
    config.countries.push(code);
  }
}

export function removeCountry(countryCode: string): void {
  const code = countryCode.toUpperCase();
  config.countries = config.countries.filter(c => c !== code);
}

export function setCountries(countries: string[]): void {
  config.countries = countries.map(c => c.toUpperCase());
}

// ============================================
// Country Check
// ============================================

export async function checkCountry(ip: string, path?: string): Promise<CountryCheckResult> {
  // If disabled, allow all
  if (!config.enabled) {
    return { allowed: true, reason: 'Country blocking disabled' };
  }

  // Check if path is in allowed paths
  if (path && config.allowedPaths?.some(p => path.startsWith(p))) {
    return { allowed: true, reason: 'Path is in allowed list' };
  }

  // Get geolocation
  const geo = await getGeolocation(ip);
  
  if (!geo || !geo.countryCode) {
    // If we can't determine country, allow by default (or block based on config)
    return { 
      allowed: true, 
      reason: 'Could not determine country',
    };
  }

  const countryCode = geo.countryCode.toUpperCase();
  const isInList = config.countries.includes(countryCode);

  if (config.mode === 'blacklist') {
    // Blacklist mode: block if country is in list
    if (isInList) {
      return {
        allowed: false,
        country: geo.country,
        countryCode,
        reason: `Country ${geo.country} (${countryCode}) is blocked`,
      };
    }
    return {
      allowed: true,
      country: geo.country,
      countryCode,
      reason: 'Country not in blacklist',
    };
  } else {
    // Whitelist mode: allow only if country is in list
    if (isInList) {
      return {
        allowed: true,
        country: geo.country,
        countryCode,
        reason: 'Country in whitelist',
      };
    }
    return {
      allowed: false,
      country: geo.country,
      countryCode,
      reason: `Country ${geo.country} (${countryCode}) not in whitelist`,
    };
  }
}

// ============================================
// Quick blocking presets
// ============================================

export function blockHighRiskCountries(): void {
  config.enabled = true;
  config.mode = 'blacklist';
  config.countries = [...HIGH_RISK_COUNTRIES];
}

export function allowOnlyCountries(countries: string[]): void {
  config.enabled = true;
  config.mode = 'whitelist';
  config.countries = countries.map(c => c.toUpperCase());
}

export function allowOnlyEU(): void {
  const euCountries = [
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
  ];
  allowOnlyCountries(euCountries);
}

// ============================================
// Cloudflare/Nginx rules generator
// ============================================

export function generateCloudflareRules(): string {
  if (!config.enabled || config.countries.length === 0) {
    return '# No country blocking rules configured';
  }

  const countries = config.countries.join(' ');
  
  if (config.mode === 'blacklist') {
    return `# Cloudflare Firewall Rule - Block Countries
# Expression:
(ip.geoip.country in {${countries}})
# Action: Block`;
  } else {
    return `# Cloudflare Firewall Rule - Allow Only Countries
# Expression:
(not ip.geoip.country in {${countries}})
# Action: Block`;
  }
}

export function generateNginxRules(): string {
  if (!config.enabled || config.countries.length === 0) {
    return '# No country blocking rules configured';
  }

  let rules = `# Nginx GeoIP2 Country Blocking
# Requires ngx_http_geoip2_module

geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
    auto_reload 1h;
    $geoip2_country_code country iso_code;
}

map $geoip2_country_code $blocked_country {
    default ${config.mode === 'blacklist' ? '0' : '1'};
`;

  for (const country of config.countries) {
    rules += `    ${country} ${config.mode === 'blacklist' ? '1' : '0'};\n`;
  }

  rules += `}

# In server block:
# if ($blocked_country) {
#     return 403;
# }`;

  return rules;
}

export function generateIPTablesRules(): string {
  if (!config.enabled || config.countries.length === 0) {
    return '# No country blocking rules configured';
  }

  let rules = `#!/bin/bash
# IPTables Country Blocking using ipset
# Requires ipset and country IP lists

# Install: apt-get install ipset

`;

  for (const country of config.countries) {
    const action = config.mode === 'blacklist' ? 'DROP' : 'ACCEPT';
    rules += `# Block/Allow ${COUNTRY_NAMES[country] || country}
ipset create ${country.toLowerCase()}_block hash:net
# Download country IPs from: https://www.ipdeny.com/ipblocks/data/countries/${country.toLowerCase()}.zone
# for ip in $(cat ${country.toLowerCase()}.zone); do ipset add ${country.toLowerCase()}_block $ip; done
iptables -A INPUT -m set --match-set ${country.toLowerCase()}_block src -j ${action}

`;
  }

  return rules;
}

// ============================================
// Statistics
// ============================================

const countryStats: Map<string, { allowed: number; blocked: number }> = new Map();

export function recordCountryCheck(countryCode: string, allowed: boolean): void {
  const stats = countryStats.get(countryCode) || { allowed: 0, blocked: 0 };
  if (allowed) {
    stats.allowed++;
  } else {
    stats.blocked++;
  }
  countryStats.set(countryCode, stats);
}

export function getCountryStats(): Array<{
  countryCode: string;
  countryName: string;
  allowed: number;
  blocked: number;
}> {
  const results: Array<{
    countryCode: string;
    countryName: string;
    allowed: number;
    blocked: number;
  }> = [];

  countryStats.forEach((stats, code) => {
    results.push({
      countryCode: code,
      countryName: COUNTRY_NAMES[code] || code,
      allowed: stats.allowed,
      blocked: stats.blocked,
    });
  });

  return results.sort((a, b) => (b.allowed + b.blocked) - (a.allowed + a.blocked));
}

export default {
  getConfig,
  setConfig,
  enableCountryBlocking,
  setMode,
  addCountry,
  removeCountry,
  setCountries,
  checkCountry,
  blockHighRiskCountries,
  allowOnlyCountries,
  allowOnlyEU,
  generateCloudflareRules,
  generateNginxRules,
  generateIPTablesRules,
  recordCountryCheck,
  getCountryStats,
  HIGH_RISK_COUNTRIES,
  COUNTRY_NAMES,
};

