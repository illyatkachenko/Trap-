/**
 * Trap - Multi-Channel Notifications
 * 
 * Send alerts to Telegram, Slack, Discord, Email, and webhooks.
 */

import type { AttackType, Severity, GeoData } from './collector';

// ============================================
// Types
// ============================================

export interface NotificationConfig {
  telegram?: TelegramConfig;
  slack?: SlackConfig;
  discord?: DiscordConfig;
  email?: EmailConfig;
  webhook?: WebhookConfig;
}

export interface TelegramConfig {
  enabled: boolean;
  botToken: string;
  chatId: string;
  threadId?: number;
}

export interface SlackConfig {
  enabled: boolean;
  webhookUrl: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

export interface DiscordConfig {
  enabled: boolean;
  webhookUrl: string;
  username?: string;
  avatarUrl?: string;
}

export interface EmailConfig {
  enabled: boolean;
  provider: 'resend' | 'sendgrid' | 'smtp';
  apiKey?: string;
  from: string;
  to: string[];
  smtpConfig?: {
    host: string;
    port: number;
    user: string;
    pass: string;
  };
}

export interface WebhookConfig {
  enabled: boolean;
  url: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT';
}

export interface AlertData {
  ip: string;
  attackType: AttackType;
  severity: Severity;
  path: string;
  details: string;
  timestamp: string;
  geo?: GeoData;
  userAgent?: string;
  blocked?: boolean;
  triggeredRule?: string;
}

// ============================================
// Configuration from environment
// ============================================

function getConfig(): NotificationConfig {
  return {
    telegram: {
      enabled: !!process.env.TELEGRAM_BOT_TOKEN,
      botToken: process.env.TELEGRAM_BOT_TOKEN || '',
      chatId: process.env.TELEGRAM_CHAT_ID || '',
      threadId: process.env.TELEGRAM_MESSAGE_THREAD_ID ? parseInt(process.env.TELEGRAM_MESSAGE_THREAD_ID) : undefined,
    },
    slack: {
      enabled: !!process.env.SLACK_WEBHOOK_URL,
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
      channel: process.env.SLACK_CHANNEL,
      username: process.env.SLACK_USERNAME || 'Trap Security',
      iconEmoji: process.env.SLACK_ICON || ':shield:',
    },
    discord: {
      enabled: !!process.env.DISCORD_WEBHOOK_URL,
      webhookUrl: process.env.DISCORD_WEBHOOK_URL || '',
      username: process.env.DISCORD_USERNAME || 'Trap Security',
      avatarUrl: process.env.DISCORD_AVATAR_URL,
    },
    email: {
      enabled: !!process.env.ALERT_EMAIL_TO,
      provider: (process.env.EMAIL_PROVIDER as any) || 'resend',
      apiKey: process.env.RESEND_API_KEY || process.env.SENDGRID_API_KEY,
      from: process.env.ALERT_EMAIL_FROM || 'security@example.com',
      to: (process.env.ALERT_EMAIL_TO || '').split(',').filter(Boolean),
    },
    webhook: {
      enabled: !!process.env.ALERT_WEBHOOK_URL,
      url: process.env.ALERT_WEBHOOK_URL || '',
      method: 'POST',
    },
  };
}

// ============================================
// Severity Colors
// ============================================

const SEVERITY_COLORS = {
  LOW: { hex: '#22c55e', name: 'green', slack: 'good', discord: 0x22c55e },
  MEDIUM: { hex: '#eab308', name: 'yellow', slack: 'warning', discord: 0xeab308 },
  HIGH: { hex: '#f97316', name: 'orange', slack: 'warning', discord: 0xf97316 },
  CRITICAL: { hex: '#ef4444', name: 'red', slack: 'danger', discord: 0xef4444 },
};

const SEVERITY_EMOJIS = {
  LOW: '🟢',
  MEDIUM: '🟡',
  HIGH: '🟠',
  CRITICAL: '🔴',
};

// ============================================
// Send to all channels
// ============================================

export async function sendAlert(data: AlertData): Promise<{
  telegram: boolean;
  slack: boolean;
  discord: boolean;
  email: boolean;
  webhook: boolean;
}> {
  const config = getConfig();
  const results = {
    telegram: false,
    slack: false,
    discord: false,
    email: false,
    webhook: false,
  };

  const promises: Promise<void>[] = [];

  if (config.telegram?.enabled) {
    promises.push(
      sendTelegram(config.telegram, data)
        .then(() => { results.telegram = true; })
        .catch(e => console.error('[Trap] Telegram error:', e))
    );
  }

  if (config.slack?.enabled) {
    promises.push(
      sendSlack(config.slack, data)
        .then(() => { results.slack = true; })
        .catch(e => console.error('[Trap] Slack error:', e))
    );
  }

  if (config.discord?.enabled) {
    promises.push(
      sendDiscord(config.discord, data)
        .then(() => { results.discord = true; })
        .catch(e => console.error('[Trap] Discord error:', e))
    );
  }

  if (config.email?.enabled && (data.severity === 'CRITICAL' || data.severity === 'HIGH')) {
    promises.push(
      sendEmail(config.email, data)
        .then(() => { results.email = true; })
        .catch(e => console.error('[Trap] Email error:', e))
    );
  }

  if (config.webhook?.enabled) {
    promises.push(
      sendWebhook(config.webhook, data)
        .then(() => { results.webhook = true; })
        .catch(e => console.error('[Trap] Webhook error:', e))
    );
  }

  await Promise.allSettled(promises);
  return results;
}

// ============================================
// Telegram
// ============================================

async function sendTelegram(config: TelegramConfig, data: AlertData): Promise<void> {
  const emoji = SEVERITY_EMOJIS[data.severity];
  
  let message = `${emoji} *${data.severity} ALERT* ${emoji}\n\n`;
  message += `*Type:* ${data.attackType}\n`;
  message += `*IP:* \`${data.ip}\`\n`;
  message += `*Path:* \`${data.path}\`\n`;
  message += `*Time:* ${data.timestamp}\n`;
  
  if (data.geo) {
    message += `*Location:* ${data.geo.city}, ${data.geo.country}\n`;
  }
  
  if (data.blocked) {
    message += `\n✅ *Auto-blocked*`;
    if (data.triggeredRule) {
      message += ` by: ${data.triggeredRule}`;
    }
  }

  const payload: any = {
    chat_id: config.chatId,
    text: message,
    parse_mode: 'Markdown',
  };

  if (config.threadId) {
    payload.message_thread_id = config.threadId;
  }

  await fetch(`https://api.telegram.org/bot${config.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// ============================================
// Slack
// ============================================

async function sendSlack(config: SlackConfig, data: AlertData): Promise<void> {
  const color = SEVERITY_COLORS[data.severity].slack;
  
  const payload = {
    channel: config.channel,
    username: config.username,
    icon_emoji: config.iconEmoji,
    attachments: [
      {
        color,
        title: `${SEVERITY_EMOJIS[data.severity]} ${data.severity} Security Alert`,
        fields: [
          { title: 'Attack Type', value: data.attackType, short: true },
          { title: 'IP Address', value: data.ip, short: true },
          { title: 'Path', value: data.path, short: false },
          { title: 'Time', value: data.timestamp, short: true },
          ...(data.geo ? [{ title: 'Location', value: `${data.geo.city}, ${data.geo.country}`, short: true }] : []),
          ...(data.blocked ? [{ title: 'Status', value: `✅ Auto-blocked${data.triggeredRule ? ` by ${data.triggeredRule}` : ''}`, short: false }] : []),
        ],
        footer: 'Trap Security System',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  await fetch(config.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// ============================================
// Discord
// ============================================

async function sendDiscord(config: DiscordConfig, data: AlertData): Promise<void> {
  const color = SEVERITY_COLORS[data.severity].discord;
  
  const payload = {
    username: config.username,
    avatar_url: config.avatarUrl,
    embeds: [
      {
        title: `${SEVERITY_EMOJIS[data.severity]} ${data.severity} Security Alert`,
        color,
        fields: [
          { name: 'Attack Type', value: data.attackType, inline: true },
          { name: 'IP Address', value: `\`${data.ip}\``, inline: true },
          { name: 'Path', value: `\`${data.path}\``, inline: false },
          ...(data.geo ? [{ name: 'Location', value: `${data.geo.city}, ${data.geo.country}`, inline: true }] : []),
          ...(data.blocked ? [{ name: 'Status', value: `✅ Auto-blocked${data.triggeredRule ? ` by ${data.triggeredRule}` : ''}`, inline: false }] : []),
        ],
        timestamp: new Date().toISOString(),
        footer: {
          text: 'Trap Security System',
        },
      },
    ],
  };

  await fetch(config.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// ============================================
// Email (Resend)
// ============================================

async function sendEmail(config: EmailConfig, data: AlertData): Promise<void> {
  if (config.provider !== 'resend' || !config.apiKey) {
    console.warn('[Trap] Email provider not configured');
    return;
  }

  const html = `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
      <div style="background: ${SEVERITY_COLORS[data.severity].hex}; color: white; padding: 20px; text-align: center;">
        <h1>${SEVERITY_EMOJIS[data.severity]} ${data.severity} Security Alert</h1>
      </div>
      <div style="padding: 20px; background: #f9f9f9;">
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Attack Type:</strong></td><td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.attackType}</td></tr>
          <tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>IP Address:</strong></td><td style="padding: 10px; border-bottom: 1px solid #ddd;"><code>${data.ip}</code></td></tr>
          <tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Path:</strong></td><td style="padding: 10px; border-bottom: 1px solid #ddd;"><code>${data.path}</code></td></tr>
          <tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Time:</strong></td><td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.timestamp}</td></tr>
          ${data.geo ? `<tr><td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Location:</strong></td><td style="padding: 10px; border-bottom: 1px solid #ddd;">${data.geo.city}, ${data.geo.country}</td></tr>` : ''}
          ${data.blocked ? `<tr><td style="padding: 10px;"><strong>Status:</strong></td><td style="padding: 10px; color: green;">✅ Auto-blocked${data.triggeredRule ? ` by ${data.triggeredRule}` : ''}</td></tr>` : ''}
        </table>
      </div>
      <div style="padding: 10px; text-align: center; color: #666; font-size: 12px;">
        Trap Security System
      </div>
    </div>
  `;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: config.from,
      to: config.to,
      subject: `[${data.severity}] Security Alert: ${data.attackType} from ${data.ip}`,
      html,
    }),
  });
}

// ============================================
// Webhook
// ============================================

async function sendWebhook(config: WebhookConfig, data: AlertData): Promise<void> {
  await fetch(config.url, {
    method: config.method || 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...config.headers,
    },
    body: JSON.stringify({
      type: 'security_alert',
      severity: data.severity,
      attack_type: data.attackType,
      ip: data.ip,
      path: data.path,
      timestamp: data.timestamp,
      geo: data.geo,
      blocked: data.blocked,
      triggered_rule: data.triggeredRule,
    }),
  });
}

// ============================================
// Email Tracker Pixel
// ============================================

export function getTrackerPixelUrl(baseUrl: string, trackingId: string): string {
  return `${baseUrl}/api/trap/pixel?id=${trackingId}`;
}

export function generateTrackerPixelHtml(baseUrl: string, trackingId: string): string {
  const url = getTrackerPixelUrl(baseUrl, trackingId);
  return `<img src="${url}" width="1" height="1" style="display:none" alt="" />`;
}

export default {
  sendAlert,
  getTrackerPixelUrl,
  generateTrackerPixelHtml,
};

