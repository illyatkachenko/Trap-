/**
 * Trap - IP Blocking Service
 * 
 * Manages blocked IP addresses with support for multiple storage backends.
 */

export interface BlockedIP {
  ip: string;
  blockedAt: Date;
  expiresAt: Date | null; // null = permanent
  reason: string;
  blockedBy: string;
  attackType: string;
  severity: string;
}

export type BlockDuration = '1h' | '24h' | '7d' | '30d' | 'permanent';

const BLOCK_STORAGE = process.env.BLOCK_STORAGE || 'memory';
const BLOCK_DURATION_DEFAULT = parseInt(process.env.BLOCK_DURATION_DEFAULT || '3600');

// In-memory storage (for development/simple deployments)
const blockedIPs = new Map<string, BlockedIP>();

/**
 * Block an IP address
 * @param ip - IP address to block
 * @param duration - How long to block
 * @param reason - Reason for blocking
 * @param blockedBy - Who initiated the block
 * @param attackType - Type of attack detected
 * @param severity - Severity level
 */
export async function blockIP(
  ip: string,
  duration: BlockDuration = '1h',
  reason: string = 'Honeypot triggered',
  blockedBy: string = 'System',
  attackType: string = 'UNKNOWN',
  severity: string = 'MEDIUM'
): Promise<boolean> {
  const now = new Date();
  let expiresAt: Date | null = null;

  switch (duration) {
    case '1h':
      expiresAt = new Date(now.getTime() + 60 * 60 * 1000);
      break;
    case '24h':
      expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      break;
    case '7d':
      expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      break;
    case 'permanent':
      expiresAt = null;
      break;
  }

  const blockData: BlockedIP = {
    ip,
    blockedAt: now,
    expiresAt,
    reason,
    blockedBy,
    attackType,
    severity,
  };

  switch (BLOCK_STORAGE) {
    case 'memory':
      blockedIPs.set(ip, blockData);
      break;
    case 'redis':
      await blockIPRedis(ip, blockData, duration);
      break;
    case 'database':
      await blockIPDatabase(ip, blockData);
      break;
    default:
      blockedIPs.set(ip, blockData);
  }

  console.log(`[Trap] Blocked IP: ${ip} for ${duration} by ${blockedBy}`);
  return true;
}

/**
 * Unblock an IP address
 * @param ip - IP address to unblock
 */
export async function unblockIP(ip: string): Promise<boolean> {
  switch (BLOCK_STORAGE) {
    case 'memory':
      return blockedIPs.delete(ip);
    case 'redis':
      return await unblockIPRedis(ip);
    case 'database':
      return await unblockIPDatabase(ip);
    default:
      return blockedIPs.delete(ip);
  }
}

/**
 * Check if an IP is blocked
 * @param ip - IP address to check
 */
export async function isIPBlocked(ip: string): Promise<boolean> {
  switch (BLOCK_STORAGE) {
    case 'memory':
      return isIPBlockedMemory(ip);
    case 'redis':
      return await isIPBlockedRedis(ip);
    case 'database':
      return await isIPBlockedDatabase(ip);
    default:
      return isIPBlockedMemory(ip);
  }
}

/**
 * Get all blocked IPs
 */
export async function getBlockedIPs(): Promise<BlockedIP[]> {
  switch (BLOCK_STORAGE) {
    case 'memory':
      return Array.from(blockedIPs.values()).filter(b => {
        if (b.expiresAt === null) return true;
        return b.expiresAt > new Date();
      });
    case 'redis':
      return await getBlockedIPsRedis();
    case 'database':
      return await getBlockedIPsDatabase();
    default:
      return Array.from(blockedIPs.values());
  }
}

/**
 * Get block info for an IP
 * @param ip - IP address to get info for
 */
export async function getBlockInfo(ip: string): Promise<BlockedIP | null> {
  switch (BLOCK_STORAGE) {
    case 'memory':
      return blockedIPs.get(ip) || null;
    case 'redis':
      return await getBlockInfoRedis(ip);
    case 'database':
      return await getBlockInfoDatabase(ip);
    default:
      return blockedIPs.get(ip) || null;
  }
}

// ============================================
// Memory Storage Implementation
// ============================================

function isIPBlockedMemory(ip: string): boolean {
  const block = blockedIPs.get(ip);
  if (!block) return false;
  
  // Check if expired
  if (block.expiresAt !== null && block.expiresAt < new Date()) {
    blockedIPs.delete(ip);
    return false;
  }
  
  return true;
}

// ============================================
// Redis Storage Implementation (Placeholder)
// ============================================

async function blockIPRedis(ip: string, data: BlockedIP, duration: BlockDuration): Promise<void> {
  // TODO: Implement Redis storage
  // const redis = await getRedisClient();
  // const ttl = duration === 'permanent' ? -1 : getDurationSeconds(duration);
  // await redis.set(`trap:blocked:${ip}`, JSON.stringify(data), ttl > 0 ? { EX: ttl } : undefined);
  console.warn('[Trap] Redis storage not implemented, using memory');
  blockedIPs.set(ip, data);
}

async function unblockIPRedis(ip: string): Promise<boolean> {
  // TODO: Implement Redis storage
  console.warn('[Trap] Redis storage not implemented, using memory');
  return blockedIPs.delete(ip);
}

async function isIPBlockedRedis(ip: string): Promise<boolean> {
  // TODO: Implement Redis storage
  console.warn('[Trap] Redis storage not implemented, using memory');
  return isIPBlockedMemory(ip);
}

async function getBlockedIPsRedis(): Promise<BlockedIP[]> {
  // TODO: Implement Redis storage
  console.warn('[Trap] Redis storage not implemented, using memory');
  return Array.from(blockedIPs.values());
}

async function getBlockInfoRedis(ip: string): Promise<BlockedIP | null> {
  // TODO: Implement Redis storage
  console.warn('[Trap] Redis storage not implemented, using memory');
  return blockedIPs.get(ip) || null;
}

// ============================================
// Database Storage Implementation (Placeholder)
// ============================================

async function blockIPDatabase(ip: string, data: BlockedIP): Promise<void> {
  // TODO: Implement database storage (Prisma, etc.)
  // await prisma.blockedIP.upsert({
  //   where: { ip },
  //   update: data,
  //   create: data,
  // });
  console.warn('[Trap] Database storage not implemented, using memory');
  blockedIPs.set(ip, data);
}

async function unblockIPDatabase(ip: string): Promise<boolean> {
  // TODO: Implement database storage
  console.warn('[Trap] Database storage not implemented, using memory');
  return blockedIPs.delete(ip);
}

async function isIPBlockedDatabase(ip: string): Promise<boolean> {
  // TODO: Implement database storage
  console.warn('[Trap] Database storage not implemented, using memory');
  return isIPBlockedMemory(ip);
}

async function getBlockedIPsDatabase(): Promise<BlockedIP[]> {
  // TODO: Implement database storage
  console.warn('[Trap] Database storage not implemented, using memory');
  return Array.from(blockedIPs.values());
}

async function getBlockInfoDatabase(ip: string): Promise<BlockedIP | null> {
  // TODO: Implement database storage
  console.warn('[Trap] Database storage not implemented, using memory');
  return blockedIPs.get(ip) || null;
}

export default {
  blockIP,
  unblockIP,
  isIPBlocked,
  getBlockedIPs,
  getBlockInfo,
};

