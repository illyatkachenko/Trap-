/**
 * Trap - Email Tracker Pixel
 * 
 * 1x1 transparent pixel that tracks when an email is opened.
 * Used to detect when attackers open emails containing fake credentials.
 */

import { NextResponse } from 'next/server';
import { collectHoneypotData } from '@/lib/honeypot/collector';

// 1x1 transparent GIF
const TRANSPARENT_GIF = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             'unknown';
  const userAgent = request.headers.get('user-agent') || 'unknown';
  const referer = request.headers.get('referer') || 'unknown';
  
  const { searchParams } = new URL(request.url);
  const trackingId = searchParams.get('id') || 'unknown';
  const source = searchParams.get('src') || 'email';

  try {
    // Log the tracking event
    await collectHoneypotData({
      ip,
      userAgent,
      path: `/api/trap/pixel?id=${trackingId}`,
      method: 'GET',
      attackType: 'DATA_EXFILTRATION',
      severity: 'HIGH',
      details: `📧 Email tracker triggered! ID: ${trackingId}. Source: ${source}. Referer: ${referer}. This likely means attacker opened an email with fake credentials!`,
    });

    console.log(`[Trap] 📧 Email tracker pixel loaded! IP: ${ip}, ID: ${trackingId}, UA: ${userAgent}`);
  } catch (error) {
    console.error('[Trap] Pixel tracking error:', error);
  }

  // Return transparent 1x1 GIF
  return new NextResponse(TRANSPARENT_GIF, {
    headers: {
      'Content-Type': 'image/gif',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    },
  });
}

