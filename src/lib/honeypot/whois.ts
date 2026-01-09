/**
 * Trap - WHOIS Lookup Service
 * 
 * Fetches WHOIS information for IP addresses.
 */

export interface WhoisData {
  ip: string;
  asn?: string;
  asnOrg?: string;
  asnCountry?: string;
  asnRegistry?: string;
  asnCidr?: string;
  asnDate?: string;
  netRange?: string;
  netName?: string;
  netHandle?: string;
  netParent?: string;
  netType?: string;
  organization?: string;
  orgName?: string;
  orgId?: string;
  address?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  regDate?: string;
  updated?: string;
  abuseEmail?: string;
  abusePhone?: string;
  raw?: string;
}

/**
 * Get WHOIS information for an IP address
 * Uses ip-api.com for basic info (free) or can be extended for full WHOIS
 * @param ip - The IP address to lookup
 * @returns WHOIS data or null if lookup fails
 */
export async function getWhoisInfo(ip: string): Promise<WhoisData | null> {
  try {
    // Use ip-api for basic ASN/Org info (free, no registration)
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=query,as,asname,isp,org,reverse`
    );

    if (!response.ok) {
      throw new Error(`WHOIS lookup failed: ${response.status}`);
    }

    const data = await response.json();

    // Parse ASN from the 'as' field (format: "AS12345 Organization Name")
    const asMatch = data.as?.match(/^(AS\d+)\s*(.*)$/);

    return {
      ip: data.query || ip,
      asn: asMatch?.[1] || data.as,
      asnOrg: asMatch?.[2] || data.asname,
      organization: data.org,
      orgName: data.isp,
    };
  } catch (error) {
    console.error('[Trap] WHOIS lookup failed:', error);
    return null;
  }
}

/**
 * Get abuse contact for an IP address
 * @param ip - The IP address to lookup
 * @returns Abuse contact email or null
 */
export async function getAbuseContact(ip: string): Promise<string | null> {
  try {
    // For full abuse contact, you'd need a proper WHOIS service
    // This is a simplified version using available free APIs
    const whois = await getWhoisInfo(ip);
    return whois?.abuseEmail || null;
  } catch (error) {
    console.error('[Trap] Abuse contact lookup failed:', error);
    return null;
  }
}

/**
 * Format WHOIS data for display
 * @param data - WHOIS data object
 * @returns Formatted string for display
 */
export function formatWhoisData(data: WhoisData): string {
  const lines: string[] = [];

  lines.push(`IP: ${data.ip}`);
  if (data.asn) lines.push(`ASN: ${data.asn}`);
  if (data.asnOrg) lines.push(`ASN Org: ${data.asnOrg}`);
  if (data.organization) lines.push(`Organization: ${data.organization}`);
  if (data.orgName) lines.push(`Org Name: ${data.orgName}`);
  if (data.netRange) lines.push(`Net Range: ${data.netRange}`);
  if (data.netName) lines.push(`Net Name: ${data.netName}`);
  if (data.country) lines.push(`Country: ${data.country}`);
  if (data.abuseEmail) lines.push(`Abuse Email: ${data.abuseEmail}`);

  return lines.join('\n');
}

export default getWhoisInfo;

