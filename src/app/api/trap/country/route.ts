/**
 * Trap - Country Blocking API
 * 
 * Manage country-based blocking rules.
 */

import { NextResponse } from 'next/server';
import {
  getConfig,
  setConfig,
  addCountry,
  removeCountry,
  checkCountry,
  blockHighRiskCountries,
  allowOnlyEU,
  generateCloudflareRules,
  generateNginxRules,
  getCountryStats,
  COUNTRY_NAMES,
  HIGH_RISK_COUNTRIES,
} from '@/lib/honeypot/country-block';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const ip = searchParams.get('ip');

  // Check specific IP
  if (action === 'check' && ip) {
    const result = await checkCountry(ip);
    return NextResponse.json(result);
  }

  // Get Cloudflare rules
  if (action === 'cloudflare') {
    return new NextResponse(generateCloudflareRules(), {
      headers: { 'Content-Type': 'text/plain' },
    });
  }

  // Get Nginx rules
  if (action === 'nginx') {
    return new NextResponse(generateNginxRules(), {
      headers: { 'Content-Type': 'text/plain' },
    });
  }

  // Get statistics
  if (action === 'stats') {
    return NextResponse.json(getCountryStats());
  }

  // Get country list
  if (action === 'countries') {
    return NextResponse.json({
      countries: COUNTRY_NAMES,
      highRisk: HIGH_RISK_COUNTRIES,
    });
  }

  // Default: return config
  return NextResponse.json(getConfig());
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { action, countries, mode, enabled, country } = body;

    switch (action) {
      case 'enable':
        setConfig({ enabled: enabled !== false });
        break;

      case 'disable':
        setConfig({ enabled: false });
        break;

      case 'setMode':
        if (mode === 'blacklist' || mode === 'whitelist') {
          setConfig({ mode });
        }
        break;

      case 'setCountries':
        if (Array.isArray(countries)) {
          setConfig({ countries });
        }
        break;

      case 'addCountry':
        if (country) {
          addCountry(country);
        }
        break;

      case 'removeCountry':
        if (country) {
          removeCountry(country);
        }
        break;

      case 'blockHighRisk':
        blockHighRiskCountries();
        break;

      case 'allowOnlyEU':
        allowOnlyEU();
        break;

      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      config: getConfig(),
    });
  } catch (error) {
    console.error('[Trap] Country config error:', error);
    return NextResponse.json({ error: 'Failed to update config' }, { status: 500 });
  }
}

