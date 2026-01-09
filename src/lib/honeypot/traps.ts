/**
 * Trap - Honeypot Trap Definitions
 * 
 * Defines paths that trigger honeypot traps and their configurations.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import type { AttackType, Severity } from './collector';

// ============================================
// Types
// ============================================

export interface HoneypotTrap {
  path: string | RegExp;
  redirectPath: string;
  attackType: AttackType;
  severity: Severity;
  description: string;
}

// ============================================
// Trap Definitions
// ============================================

export const HONEYPOT_TRAPS: HoneypotTrap[] = [
  // ==========================================
  // Environment Variable Disclosure
  // ==========================================
  { 
    path: '/.env', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env file' 
  },
  { 
    path: '/.env.local', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.local file' 
  },
  { 
    path: '/.env.production', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.production file' 
  },
  { 
    path: '/.env.development', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.development file' 
  },
  { 
    path: '/env', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access /env endpoint' 
  },
  { 
    path: '/config.env', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access config.env file' 
  },
  { 
    path: '/.env.backup', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.backup file' 
  },
  { 
    path: '/.env.bak', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.bak file' 
  },
  { 
    path: '/.env.old', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.old file' 
  },
  { 
    path: '/.env.save', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .env.save file' 
  },
  { 
    path: '/.env.example', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'MEDIUM', 
    description: 'Attempt to access .env.example file' 
  },

  // ==========================================
  // Git Repository Disclosure
  // ==========================================
  { 
    path: /^\/\.git(\/.*)?$/, 
    redirectPath: '/api/trap/env', 
    attackType: 'GIT_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .git directory' 
  },
  { 
    path: '/.gitignore', 
    redirectPath: '/api/trap/env', 
    attackType: 'GIT_DISCLOSURE', 
    severity: 'HIGH', 
    description: 'Attempt to access .gitignore file' 
  },
  { 
    path: '/.gitconfig', 
    redirectPath: '/api/trap/env', 
    attackType: 'GIT_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access .gitconfig file' 
  },

  // ==========================================
  // Common Admin Panels / CMS
  // ==========================================
  { 
    path: '/wp-admin', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access WordPress admin panel' 
  },
  { 
    path: '/wp-login.php', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access WordPress login page' 
  },
  { 
    path: '/wp-content', 
    redirectPath: '/api/trap/creds', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access WordPress content' 
  },
  { 
    path: '/phpmyadmin', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access phpMyAdmin' 
  },
  { 
    path: '/pma', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access phpMyAdmin (pma)' 
  },
  { 
    path: '/adminer', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access Adminer' 
  },
  { 
    path: '/adminer.php', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access Adminer' 
  },
  { 
    path: '/admin', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access generic admin panel' 
  },
  { 
    path: '/administrator', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access Joomla admin' 
  },
  { 
    path: '/login', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'MEDIUM', 
    description: 'Attempt to access generic login page' 
  },
  { 
    path: '/admin.php', 
    redirectPath: '/api/trap/creds', 
    attackType: 'BRUTE_FORCE', 
    severity: 'HIGH', 
    description: 'Attempt to access admin.php' 
  },

  // ==========================================
  // Backup Files
  // ==========================================
  { 
    path: /\.sql(\.zip|\.gz|\.tgz|\.rar|\.7z)?$/i, 
    redirectPath: '/api/trap/env', 
    attackType: 'DATA_EXFILTRATION', 
    severity: 'CRITICAL', 
    description: 'Attempt to access SQL backup file' 
  },
  { 
    path: /backup(\.zip|\.gz|\.tgz|\.rar|\.7z|\.tar)?$/i, 
    redirectPath: '/api/trap/env', 
    attackType: 'DATA_EXFILTRATION', 
    severity: 'CRITICAL', 
    description: 'Attempt to access backup file' 
  },
  { 
    path: /dump(\.sql|\.zip|\.gz|\.tgz|\.rar)?$/i, 
    redirectPath: '/api/trap/env', 
    attackType: 'DATA_EXFILTRATION', 
    severity: 'CRITICAL', 
    description: 'Attempt to access database dump file' 
  },
  { 
    path: '/db.sql', 
    redirectPath: '/api/trap/env', 
    attackType: 'DATA_EXFILTRATION', 
    severity: 'CRITICAL', 
    description: 'Attempt to access db.sql' 
  },
  { 
    path: '/database.sql', 
    redirectPath: '/api/trap/env', 
    attackType: 'DATA_EXFILTRATION', 
    severity: 'CRITICAL', 
    description: 'Attempt to access database.sql' 
  },

  // ==========================================
  // Configuration Files
  // ==========================================
  { 
    path: /config\.(php|json|xml|yml|yaml|ini)$/i, 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access configuration file' 
  },
  { 
    path: '/secrets.json', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access secrets.json file' 
  },
  { 
    path: '/credentials.json', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access credentials.json file' 
  },
  { 
    path: '/settings.json', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'HIGH', 
    description: 'Attempt to access settings.json file' 
  },

  // ==========================================
  // Common PHP Files (often vulnerable)
  // ==========================================
  { 
    path: /\.php$/i, 
    redirectPath: '/api/trap/creds', 
    attackType: 'WEBSHELL_UPLOAD', 
    severity: 'HIGH', 
    description: 'Attempt to access or execute PHP file' 
  },

  // ==========================================
  // AWS / Cloud Credentials
  // ==========================================
  { 
    path: '/.aws/credentials', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access AWS credentials' 
  },
  { 
    path: '/.docker/config.json', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access Docker config' 
  },
  { 
    path: '/.kube/config', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access Kubernetes config' 
  },

  // ==========================================
  // SSH Keys
  // ==========================================
  { 
    path: '/.ssh/id_rsa', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access SSH private key' 
  },
  { 
    path: '/.ssh/id_ed25519', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'CRITICAL', 
    description: 'Attempt to access SSH private key' 
  },
  { 
    path: '/.ssh/authorized_keys', 
    redirectPath: '/api/trap/env', 
    attackType: 'ENV_DISCLOSURE', 
    severity: 'HIGH', 
    description: 'Attempt to access SSH authorized keys' 
  },

  // ==========================================
  // Server Files
  // ==========================================
  { 
    path: '/server-status', 
    redirectPath: '/api/trap/env', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access Apache server-status' 
  },
  { 
    path: '/nginx_status', 
    redirectPath: '/api/trap/env', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access Nginx status' 
  },
  { 
    path: '/phpinfo.php', 
    redirectPath: '/api/trap/creds', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access phpinfo' 
  },

  // ==========================================
  // Debug Endpoints
  // ==========================================
  { 
    path: '/debug', 
    redirectPath: '/api/trap/creds', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access debug endpoint' 
  },
  { 
    path: '/_debug', 
    redirectPath: '/api/trap/creds', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access debug endpoint' 
  },
  { 
    path: '/console', 
    redirectPath: '/api/trap/creds', 
    attackType: 'INFO_GATHERING', 
    severity: 'MEDIUM', 
    description: 'Attempt to access console' 
  },

  // ==========================================
  // Other Common Attack Vectors
  // ==========================================
  { 
    path: '/.well-known/security.txt', 
    redirectPath: '/api/trap/env', 
    attackType: 'INFO_GATHERING', 
    severity: 'LOW', 
    description: 'Attempt to access security.txt' 
  },
  { 
    path: '/crossdomain.xml', 
    redirectPath: '/api/trap/env', 
    attackType: 'INFO_GATHERING', 
    severity: 'LOW', 
    description: 'Attempt to access crossdomain.xml' 
  },
  { 
    path: '/clientaccesspolicy.xml', 
    redirectPath: '/api/trap/env', 
    attackType: 'INFO_GATHERING', 
    severity: 'LOW', 
    description: 'Attempt to access clientaccesspolicy.xml' 
  },
  { 
    path: '/autodiscover', 
    redirectPath: '/api/trap/creds', 
    attackType: 'COMMAND_INJECTION', 
    severity: 'HIGH', 
    description: 'Attempt to exploit Exchange autodiscover' 
  },
];

// ============================================
// Trap Middleware Function
// ============================================

export function honeypotTraps(request: NextRequest, ip: string): NextResponse | null {
  const { pathname } = request.nextUrl;

  for (const trap of HONEYPOT_TRAPS) {
    let matched = false;

    if (typeof trap.path === 'string') {
      matched = pathname === trap.path || pathname.toLowerCase() === trap.path.toLowerCase();
    } else if (trap.path instanceof RegExp) {
      matched = trap.path.test(pathname);
    }

    if (matched) {
      console.warn(`[Trap] ${trap.severity} | ${trap.attackType} | IP: ${ip} | Path: ${pathname}`);
      
      // Rewrite to the trap endpoint
      const trapUrl = new URL(trap.redirectPath, request.url);
      trapUrl.searchParams.set('original_path', pathname);
      trapUrl.searchParams.set('trap_type', trap.attackType);
      trapUrl.searchParams.set('severity', trap.severity);
      
      return NextResponse.rewrite(trapUrl);
    }
  }

  return null;
}

export default honeypotTraps;

