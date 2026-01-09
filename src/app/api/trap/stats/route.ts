/**
 * Trap - Statistics API
 * 
 * Returns attack statistics for the dashboard.
 */

import { NextResponse } from 'next/server';
import { getStats, exportToCSV, exportToJSON, generateDashboardHTML } from '@/lib/honeypot/statistics';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const format = searchParams.get('format');
  const hours = parseInt(searchParams.get('hours') || '24');
  
  const now = Date.now();
  const timeRange = {
    start: now - hours * 60 * 60 * 1000,
    end: now,
  };

  // Dashboard HTML
  if (format === 'html') {
    const baseUrl = new URL(request.url).origin;
    const html = generateDashboardHTML(baseUrl);
    return new NextResponse(html, {
      headers: { 'Content-Type': 'text/html' },
    });
  }

  // CSV export
  if (format === 'csv') {
    const csv = exportToCSV(timeRange);
    return new NextResponse(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="trap-attacks.csv"',
      },
    });
  }

  // JSON stats (default)
  const stats = getStats(timeRange);
  
  return NextResponse.json(stats);
}

