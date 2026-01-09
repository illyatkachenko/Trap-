/**
 * Trap - IP Geolocation Service
 * 
 * Fetches geolocation data for IP addresses using various providers.
 */

export interface GeoData {
  status: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  proxy?: boolean;
  hosting?: boolean;
  mobile?: boolean;
}

const GEO_PROVIDER = process.env.GEO_PROVIDER || 'ip-api';
const GEO_API_KEY = process.env.GEO_API_KEY || '';

/**
 * Get geolocation data for an IP address
 * @param ip - The IP address to lookup
 * @returns Geolocation data or null if lookup fails
 */
export async function getGeolocation(ip: string): Promise<GeoData | null> {
  // Skip for private/local IPs
  if (isPrivateIP(ip)) {
    return null;
  }

  try {
    switch (GEO_PROVIDER) {
      case 'ip-api':
        return await getFromIpApi(ip);
      case 'ipinfo':
        return await getFromIpInfo(ip);
      default:
        return await getFromIpApi(ip);
    }
  } catch (error) {
    console.error('[Trap] Geolocation lookup failed:', error);
    return null;
  }
}

/**
 * Check if an IP is private/local
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^0\./,
    /^169\.254\./,
  ];

  // Check for localhost
  if (ip === 'localhost' || ip === '::1' || ip === 'unknown') {
    return true;
  }

  // Check IPv4 private ranges
  for (const range of privateRanges) {
    if (range.test(ip)) {
      return true;
    }
  }

  // Check for IPv6 private addresses
  if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) {
    return true;
  }

  return false;
}

/**
 * Fetch geolocation from ip-api.com (free tier: 45 requests/minute)
 */
async function getFromIpApi(ip: string): Promise<GeoData | null> {
  const fields = 'status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,mobile';
  const url = `http://ip-api.com/json/${ip}?fields=${fields}`;

  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`ip-api returned ${response.status}`);
  }

  const data = await response.json();

  if (data.status !== 'success') {
    console.warn('[Trap] ip-api lookup failed:', data.message);
    return null;
  }

  return data;
}

/**
 * Fetch geolocation from ipinfo.io (requires API key for full data)
 */
async function getFromIpInfo(ip: string): Promise<GeoData | null> {
  const url = GEO_API_KEY 
    ? `https://ipinfo.io/${ip}?token=${GEO_API_KEY}`
    : `https://ipinfo.io/${ip}/json`;

  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`ipinfo returned ${response.status}`);
  }

  const data = await response.json();

  // Convert ipinfo format to our standard format
  const [lat, lon] = (data.loc || '0,0').split(',').map(Number);

  return {
    status: 'success',
    country: data.country || '',
    countryCode: data.country || '',
    region: data.region || '',
    regionName: data.region || '',
    city: data.city || '',
    zip: data.postal || '',
    lat,
    lon,
    timezone: data.timezone || '',
    isp: data.org || '',
    org: data.org || '',
    as: data.org || '',
    proxy: false,
    hosting: false,
    mobile: false,
  };
}

export default getGeolocation;

