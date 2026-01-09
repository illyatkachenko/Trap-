/**
 * Trap - Telegram Actions Endpoint
 * 
 * Handles Telegram callback queries for interactive threat management.
 * This endpoint should be set as the Telegram webhook URL.
 */

import { NextResponse } from 'next/server';
import { getWhoisInfo, formatWhoisData } from '@/lib/honeypot/whois';
import { getGeolocation } from '@/lib/honeypot/geolocation';
import { blockIP, unblockIP, isIPBlocked, getBlockedIPs, getBlockInfo } from '@/lib/honeypot/blocker';

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';
const TELEGRAM_MESSAGE_THREAD_ID = process.env.TELEGRAM_MESSAGE_THREAD_ID ? 
  parseInt(process.env.TELEGRAM_MESSAGE_THREAD_ID) : undefined;
const TELEGRAM_API_URL = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}`;

// ============================================
// Telegram API Helpers
// ============================================

async function sendTelegramMessage(text: string, replyToMessageId?: number): Promise<any> {
  const url = `${TELEGRAM_API_URL}/sendMessage`;
  const payload: Record<string, any> = {
    chat_id: TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'Markdown',
  };

  if (TELEGRAM_MESSAGE_THREAD_ID) {
    payload.message_thread_id = TELEGRAM_MESSAGE_THREAD_ID;
  }

  if (replyToMessageId) {
    payload.reply_to_message_id = replyToMessageId;
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await response.json();
  } catch (error) {
    console.error('[Trap] Telegram send error:', error);
    throw error;
  }
}

async function answerCallbackQuery(
  callbackQueryId: string, 
  text: string, 
  showAlert: boolean = false
): Promise<any> {
  const url = `${TELEGRAM_API_URL}/answerCallbackQuery`;
  const payload = {
    callback_query_id: callbackQueryId,
    text,
    show_alert: showAlert,
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return await response.json();
  } catch (error) {
    console.error('[Trap] Callback answer error:', error);
    throw error;
  }
}

// ============================================
// POST Handler (Telegram Webhook)
// ============================================

export async function POST(request: Request) {
  let body: Record<string, any>;
  
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const callbackQuery = body.callback_query;

  if (!callbackQuery) {
    // Not a callback query, might be a regular message
    return NextResponse.json({ ok: true });
  }

  const data = callbackQuery.data || '';
  const [action, ip, attackId] = data.split(':');
  const messageId = callbackQuery.message?.message_id;
  const fromUser = callbackQuery.from?.username || callbackQuery.from?.first_name || 'Unknown';

  let responseText = `Action "${action}" for IP ${ip}`;
  let showAlert = false;

  try {
    switch (action) {
      // Block actions
      case 'b1': { // Block 1 hour
        if (await isIPBlocked(ip)) {
          responseText = `⚠️ IP ${ip} is already blocked!`;
          showAlert = true;
        } else {
          await blockIP(ip, '1h', 'Honeypot triggered', fromUser);
          responseText = `🚫 IP ${ip} blocked for 1 hour`;
          await sendTelegramMessage(`🚫 *IP ${ip} blocked for 1 hour by ${fromUser}*`, messageId);
        }
        break;
      }

      case 'b24': { // Block 24 hours
        if (await isIPBlocked(ip)) {
          responseText = `⚠️ IP ${ip} is already blocked!`;
          showAlert = true;
        } else {
          await blockIP(ip, '24h', 'Honeypot triggered', fromUser);
          responseText = `🚫 IP ${ip} blocked for 24 hours`;
          await sendTelegramMessage(`🚫 *IP ${ip} blocked for 24 hours by ${fromUser}*`, messageId);
        }
        break;
      }

      case 'bp': { // Block permanent
        if (await isIPBlocked(ip)) {
          responseText = `⚠️ IP ${ip} is already blocked!`;
          showAlert = true;
        } else {
          await blockIP(ip, 'permanent', 'Honeypot triggered', fromUser);
          responseText = `🚫 IP ${ip} blocked permanently`;
          await sendTelegramMessage(`🚫 *IP ${ip} blocked permanently by ${fromUser}*`, messageId);
        }
        break;
      }

      case 'ub': { // Unblock
        if (await unblockIP(ip)) {
          responseText = `🔓 IP ${ip} unblocked`;
          await sendTelegramMessage(`🔓 *IP ${ip} unblocked by ${fromUser}*`, messageId);
        } else {
          responseText = `⚠️ IP ${ip} was not blocked`;
          showAlert = true;
        }
        break;
      }

      // WHOIS lookup
      case 'w': {
        responseText = `Fetching WHOIS for ${ip}...`;
        await answerCallbackQuery(callbackQuery.id, responseText);
        
        const whoisData = await getWhoisInfo(ip);
        if (whoisData) {
          const formatted = formatWhoisData(whoisData);
          await sendTelegramMessage(
            `📋 *WHOIS for ${ip}:*\n\`\`\`\n${formatted}\n\`\`\``, 
            messageId
          );
          responseText = `WHOIS sent to chat`;
        } else {
          responseText = `❌ WHOIS lookup failed`;
          showAlert = true;
        }
        break;
      }

      // Report abuse
      case 'r': {
        responseText = `Preparing abuse report for ${ip}...`;
        const whoisData = await getWhoisInfo(ip);
        const geoData = await getGeolocation(ip);
        
        let reportMsg = `📧 *Abuse Report for ${ip}*\n\n`;
        reportMsg += `*Prepared by:* ${fromUser}\n`;
        reportMsg += `*Time:* ${new Date().toISOString()}\n\n`;
        
        if (geoData) {
          reportMsg += `*Location:* ${geoData.city}, ${geoData.country}\n`;
          reportMsg += `*ISP:* ${geoData.isp}\n`;
          reportMsg += `*ASN:* ${geoData.as}\n`;
        }
        
        if (whoisData?.abuseEmail) {
          reportMsg += `\n*Abuse Contact:* ${whoisData.abuseEmail}\n`;
        }
        
        reportMsg += `\n_Send this report to the ISP's abuse department._`;
        
        await sendTelegramMessage(reportMsg, messageId);
        responseText = `Report prepared`;
        break;
      }

      // Geo info
      case 'g': {
        responseText = `Fetching geo info for ${ip}...`;
        await answerCallbackQuery(callbackQuery.id, responseText);
        
        const geoData = await getGeolocation(ip);
        if (geoData) {
          let geoMsg = `🌍 *Geolocation for ${ip}:*\n\n`;
          geoMsg += `*Country:* ${geoData.country} (${geoData.countryCode})\n`;
          geoMsg += `*City:* ${geoData.city}\n`;
          geoMsg += `*Region:* ${geoData.regionName}\n`;
          geoMsg += `*Timezone:* ${geoData.timezone}\n`;
          geoMsg += `*ISP:* ${geoData.isp}\n`;
          geoMsg += `*Org:* ${geoData.org}\n`;
          geoMsg += `*ASN:* ${geoData.as}\n`;
          geoMsg += `*Coords:* [${geoData.lat}, ${geoData.lon}](https://www.google.com/maps?q=${geoData.lat},${geoData.lon})\n`;
          if (geoData.proxy) geoMsg += `*Proxy/VPN:* ✅ Yes\n`;
          if (geoData.hosting) geoMsg += `*Hosting/DC:* ✅ Yes\n`;
          
          await sendTelegramMessage(geoMsg, messageId);
          responseText = `Geo info sent`;
        } else {
          responseText = `❌ Geo lookup failed`;
          showAlert = true;
        }
        break;
      }

      // Investigate
      case 'i': {
        responseText = `Marked for investigation`;
        await sendTelegramMessage(
          `🔍 *Attack ${attackId || 'unknown'} from ${ip} marked for investigation by ${fromUser}*`, 
          messageId
        );
        break;
      }

      // False positive
      case 'fp': {
        responseText = `Marked as false positive`;
        await unblockIP(ip); // Unblock if blocked
        await sendTelegramMessage(
          `✅ *Attack from ${ip} marked as false positive by ${fromUser}*`, 
          messageId
        );
        break;
      }

      default: {
        responseText = `Unknown action: ${action}`;
        showAlert = true;
      }
    }
  } catch (error) {
    console.error('[Trap] Action error:', error);
    responseText = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    showAlert = true;
  }

  await answerCallbackQuery(callbackQuery.id, responseText, showAlert);
  return NextResponse.json({ ok: true });
}

// ============================================
// GET Handler (API for checking/managing blocks)
// ============================================

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const action = searchParams.get('action');
  const ip = searchParams.get('ip');

  switch (action) {
    case 'check': {
      if (!ip) {
        return NextResponse.json({ error: 'IP required' }, { status: 400 });
      }
      const isBlocked = await isIPBlocked(ip);
      const blockInfo = isBlocked ? await getBlockInfo(ip) : null;
      return NextResponse.json({ 
        ip, 
        isBlocked, 
        blockInfo 
      });
    }

    case 'blocked': {
      const blockedList = await getBlockedIPs();
      return NextResponse.json({ 
        blocked: blockedList, 
        count: blockedList.length 
      });
    }

    case 'unblock': {
      if (!ip) {
        return NextResponse.json({ error: 'IP required' }, { status: 400 });
      }
      const success = await unblockIP(ip);
      return NextResponse.json({ 
        ok: success, 
        message: success ? `IP ${ip} unblocked` : `IP ${ip} was not blocked` 
      });
    }

    case 'block': {
      if (!ip) {
        return NextResponse.json({ error: 'IP required' }, { status: 400 });
      }
      const duration = (searchParams.get('duration') || '1h') as any;
      const reason = searchParams.get('reason') || 'Manual block';
      await blockIP(ip, duration, reason, 'API');
      return NextResponse.json({ 
        ok: true, 
        message: `IP ${ip} blocked for ${duration}` 
      });
    }

    default: {
      return NextResponse.json({ 
        error: 'Invalid action',
        available: ['check', 'blocked', 'unblock', 'block']
      }, { status: 400 });
    }
  }
}

