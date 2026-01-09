/**
 * Trap - Example Middleware Integration
 * 
 * Copy this to your project's middleware.ts and customize as needed.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { honeypotTraps } from '@/lib/honeypot/traps';
import { isIPBlocked } from '@/lib/honeypot/blocker';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // Get client IP
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
             request.headers.get('x-real-ip') || 
             request.headers.get('cf-connecting-ip') ||
             'unknown';

  // ==========================================
  // 1. Check if IP is blocked
  // ==========================================
  if (ip !== 'unknown' && await isIPBlocked(ip)) {
    console.error(`[Trap] Blocked IP attempted access: ${ip} to ${pathname}`);
    return NextResponse.json(
      { error: 'Access denied' },
      { status: 403 }
    );
  }

  // ==========================================
  // 2. Check honeypot traps
  // ==========================================
  // Skip honeypot for your legitimate API endpoints
  const legitimateApiPaths = [
    '/api/auth',
    '/api/users',
    '/api/products',
    // Add your legitimate API paths here
  ];

  const isLegitimateApi = legitimateApiPaths.some(path => 
    pathname.startsWith(path)
  );

  if (!isLegitimateApi) {
    const trapResponse = honeypotTraps(request, ip);
    if (trapResponse) {
      return trapResponse;
    }
  }

  // ==========================================
  // 3. Your existing middleware logic
  // ==========================================
  
  // Example: Rate limiting
  // const rateLimitResult = await rateLimit(request);
  // if (!rateLimitResult.success) {
  //   return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  // }

  // Example: Authentication check
  // const session = await getSession(request);
  // if (pathname.startsWith('/admin') && !session?.isAdmin) {
  //   return NextResponse.redirect(new URL('/login', request.url));
  // }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public/).*)',
  ],
};

