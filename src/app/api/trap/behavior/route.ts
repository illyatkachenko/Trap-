/**
 * Trap - Behavior Analysis API
 * 
 * Receives behavior data (mouse, typing) from client-side tracking.
 */

import { NextResponse } from 'next/server';
import { analyzeBehaviorData } from '@/lib/honeypot/behavior';
import { collectHoneypotData } from '@/lib/honeypot/collector';

export async function POST(request: Request) {
  try {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0] || 
               request.headers.get('x-real-ip') || 
               'unknown';
    const userAgent = request.headers.get('user-agent') || 'unknown';
    
    const data = await request.json();
    const analysis = analyzeBehaviorData(data);

    // If bot detected, send alert
    if (analysis.isBot && analysis.botConfidence > 0.7) {
      await collectHoneypotData({
        ip,
        userAgent,
        path: '/api/trap/behavior',
        method: 'POST',
        attackType: 'SCANNER',
        severity: analysis.botConfidence > 0.9 ? 'HIGH' : 'MEDIUM',
        details: `Bot detected! Confidence: ${Math.round(analysis.botConfidence * 100)}%. Risk score: ${analysis.riskScore}`,
      });
    }

    return NextResponse.json({
      isBot: analysis.isBot,
      confidence: analysis.botConfidence,
      riskScore: analysis.riskScore,
    });
  } catch (error) {
    console.error('[Trap] Behavior analysis error:', error);
    return NextResponse.json({ error: 'Analysis failed' }, { status: 500 });
  }
}

