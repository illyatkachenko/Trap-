/**
 * Trap - API Key Monitoring API
 * 
 * Monitor and track API key usage, detect fake key attempts.
 */

import { NextResponse } from 'next/server';
import {
  isFakeKey,
  trackFakeKeyUsage,
  getKeyUsageStats,
  getFakeKeyAttempts,
} from '@/lib/honeypot/key-monitor';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const keyPrefix = searchParams.get('key');

  // Get fake key attempts
  if (action === 'fakeAttempts') {
    return NextResponse.json({
      attempts: getFakeKeyAttempts(),
    });
  }

  // Get usage stats
  const stats = getKeyUsageStats(keyPrefix || undefined);
  return NextResponse.json(stats);
}

export async function POST(request: Request) {
  try {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
               request.headers.get('x-real-ip') || 
               'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    const body = await request.json();
    const { key, service, action } = body;

    if (!key) {
      return NextResponse.json({ error: 'API key required' }, { status: 400 });
    }

    // Check if fake key
    const fakeCheck = isFakeKey(key);
    
    if (fakeCheck.isFake) {
      // Track the fake key usage
      await trackFakeKeyUsage(key, ip, userAgent, service || 'unknown', action || 'unknown');
      
      return NextResponse.json({
        isFake: true,
        keyType: fakeCheck.keyType,
        message: fakeCheck.message,
        tracked: true,
      });
    }

    return NextResponse.json({
      isFake: false,
      message: 'Key appears to be legitimate',
    });
  } catch (error) {
    console.error('[Trap] Key check error:', error);
    return NextResponse.json({ error: 'Failed to check key' }, { status: 500 });
  }
}

