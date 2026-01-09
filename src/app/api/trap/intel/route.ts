/**
 * Trap - Threat Intelligence API
 * 
 * Check IP reputation across multiple threat intel sources.
 */

import { NextResponse } from 'next/server';
import { checkAllSources, autoReportAttack, checkAbuseIPDB } from '@/lib/honeypot/threat-intel';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = searchParams.get('ip');
  const source = searchParams.get('source'); // Optional: abuseipdb, virustotal, greynoise

  if (!ip) {
    return NextResponse.json({ error: 'IP address required' }, { status: 400 });
  }

  try {
    if (source === 'abuseipdb') {
      const result = await checkAbuseIPDB(ip);
      return NextResponse.json(result);
    }

    // Check all sources
    const result = await checkAllSources(ip);
    return NextResponse.json(result);
  } catch (error) {
    console.error('[Trap] Threat intel error:', error);
    return NextResponse.json({ error: 'Failed to check IP' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { ip, attackType, path, details } = body;

    if (!ip || !attackType) {
      return NextResponse.json({ error: 'IP and attackType required' }, { status: 400 });
    }

    // Report to AbuseIPDB
    const reported = await autoReportAttack(
      ip,
      attackType,
      path || '/',
      details || 'Attack detected by Trap honeypot'
    );

    return NextResponse.json({ 
      reported,
      message: reported ? 'Successfully reported to AbuseIPDB' : 'Failed to report (API key may not be configured)',
    });
  } catch (error) {
    console.error('[Trap] Report error:', error);
    return NextResponse.json({ error: 'Failed to report' }, { status: 500 });
  }
}

