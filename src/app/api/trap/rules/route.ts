/**
 * Trap - Auto-Block Rules API
 * 
 * Manage auto-blocking rules.
 */

import { NextResponse } from 'next/server';
import {
  getRules,
  setRules,
  addRule,
  removeRule,
  enableRule,
  getAttackStats,
  DEFAULT_RULES,
} from '@/lib/honeypot/autoblock';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const ip = searchParams.get('ip');

  // Get attack stats for specific IP
  if (action === 'stats') {
    return NextResponse.json(getAttackStats(ip || undefined));
  }

  // Get default rules
  if (action === 'defaults') {
    return NextResponse.json({ rules: DEFAULT_RULES });
  }

  // Default: return active rules
  return NextResponse.json({ rules: getRules() });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { action, rule, ruleId, enabled, rules } = body;

    switch (action) {
      case 'add':
        if (rule) {
          addRule(rule);
        }
        break;

      case 'remove':
        if (ruleId) {
          removeRule(ruleId);
        }
        break;

      case 'enable':
        if (ruleId !== undefined) {
          enableRule(ruleId, enabled !== false);
        }
        break;

      case 'setAll':
        if (Array.isArray(rules)) {
          setRules(rules);
        }
        break;

      case 'reset':
        setRules([...DEFAULT_RULES]);
        break;

      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      rules: getRules(),
    });
  } catch (error) {
    console.error('[Trap] Rules config error:', error);
    return NextResponse.json({ error: 'Failed to update rules' }, { status: 500 });
  }
}

