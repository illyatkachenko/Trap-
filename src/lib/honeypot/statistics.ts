/**
 * Trap - Attack Statistics & Dashboard Data
 * 
 * Collects and aggregates attack statistics for dashboard display.
 */

import type { AttackType, Severity } from './collector';

// ============================================
// Types
// ============================================

export interface AttackRecord {
  id: string;
  ip: string;
  attackType: AttackType;
  severity: Severity;
  path: string;
  timestamp: number;
  country?: string;
  countryCode?: string;
  city?: string;
  userAgent?: string;
  blocked: boolean;
  triggeredRule?: string;
}

export interface DashboardStats {
  totalAttacks: number;
  blockedAttacks: number;
  uniqueIPs: number;
  attacksByType: Record<string, number>;
  attacksBySeverity: Record<string, number>;
  attacksByCountry: Record<string, number>;
  attacksByHour: number[];
  topAttackers: Array<{ ip: string; count: number; country?: string }>;
  topPaths: Array<{ path: string; count: number }>;
  recentAttacks: AttackRecord[];
  timeline: Array<{ timestamp: number; count: number }>;
}

export interface TimeRange {
  start: number;
  end: number;
}

// ============================================
// In-memory storage
// ============================================

const attacks: AttackRecord[] = [];
const MAX_ATTACKS = 10000; // Keep last 10k attacks in memory

// ============================================
// Record Attack
// ============================================

export function recordAttack(attack: Omit<AttackRecord, 'id'>): AttackRecord {
  const record: AttackRecord = {
    ...attack,
    id: generateId(),
  };

  attacks.push(record);

  // Keep only last MAX_ATTACKS
  if (attacks.length > MAX_ATTACKS) {
    attacks.shift();
  }

  return record;
}

function generateId(): string {
  return `atk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// ============================================
// Get Statistics
// ============================================

export function getStats(timeRange?: TimeRange): DashboardStats {
  const now = Date.now();
  const defaultRange: TimeRange = {
    start: now - 24 * 60 * 60 * 1000, // Last 24 hours
    end: now,
  };
  const range = timeRange || defaultRange;

  // Filter attacks by time range
  const filteredAttacks = attacks.filter(
    a => a.timestamp >= range.start && a.timestamp <= range.end
  );

  // Calculate statistics
  const attacksByType: Record<string, number> = {};
  const attacksBySeverity: Record<string, number> = {};
  const attacksByCountry: Record<string, number> = {};
  const attacksByHour: number[] = new Array(24).fill(0);
  const ipCounts: Map<string, { count: number; country?: string }> = new Map();
  const pathCounts: Map<string, number> = new Map();
  let blockedCount = 0;

  for (const attack of filteredAttacks) {
    // By type
    attacksByType[attack.attackType] = (attacksByType[attack.attackType] || 0) + 1;

    // By severity
    attacksBySeverity[attack.severity] = (attacksBySeverity[attack.severity] || 0) + 1;

    // By country
    if (attack.countryCode) {
      attacksByCountry[attack.countryCode] = (attacksByCountry[attack.countryCode] || 0) + 1;
    }

    // By hour
    const hour = new Date(attack.timestamp).getHours();
    attacksByHour[hour]++;

    // IP counts
    const ipData = ipCounts.get(attack.ip) || { count: 0, country: attack.country };
    ipData.count++;
    ipCounts.set(attack.ip, ipData);

    // Path counts
    pathCounts.set(attack.path, (pathCounts.get(attack.path) || 0) + 1);

    // Blocked count
    if (attack.blocked) {
      blockedCount++;
    }
  }

  // Top attackers
  const topAttackers = Array.from(ipCounts.entries())
    .map(([ip, data]) => ({ ip, count: data.count, country: data.country }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Top paths
  const topPaths = Array.from(pathCounts.entries())
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Timeline (hourly buckets)
  const timeline = generateTimeline(filteredAttacks, range);

  return {
    totalAttacks: filteredAttacks.length,
    blockedAttacks: blockedCount,
    uniqueIPs: ipCounts.size,
    attacksByType,
    attacksBySeverity,
    attacksByCountry,
    attacksByHour,
    topAttackers,
    topPaths,
    recentAttacks: filteredAttacks.slice(-50).reverse(),
    timeline,
  };
}

function generateTimeline(
  attacks: AttackRecord[],
  range: TimeRange
): Array<{ timestamp: number; count: number }> {
  const bucketSize = 60 * 60 * 1000; // 1 hour
  const buckets: Map<number, number> = new Map();

  // Initialize buckets
  for (let t = range.start; t <= range.end; t += bucketSize) {
    const bucketStart = Math.floor(t / bucketSize) * bucketSize;
    buckets.set(bucketStart, 0);
  }

  // Count attacks per bucket
  for (const attack of attacks) {
    const bucketStart = Math.floor(attack.timestamp / bucketSize) * bucketSize;
    buckets.set(bucketStart, (buckets.get(bucketStart) || 0) + 1);
  }

  return Array.from(buckets.entries())
    .map(([timestamp, count]) => ({ timestamp, count }))
    .sort((a, b) => a.timestamp - b.timestamp);
}

// ============================================
// Get Attack Details
// ============================================

export function getAttack(id: string): AttackRecord | undefined {
  return attacks.find(a => a.id === id);
}

export function getAttacksByIP(ip: string, limit: number = 100): AttackRecord[] {
  return attacks
    .filter(a => a.ip === ip)
    .slice(-limit)
    .reverse();
}

export function getAttacksByType(type: AttackType, limit: number = 100): AttackRecord[] {
  return attacks
    .filter(a => a.attackType === type)
    .slice(-limit)
    .reverse();
}

export function getRecentAttacks(limit: number = 50): AttackRecord[] {
  return attacks.slice(-limit).reverse();
}

// ============================================
// Export Data
// ============================================

export function exportToCSV(timeRange?: TimeRange): string {
  const stats = getStats(timeRange);
  const headers = ['ID', 'Timestamp', 'IP', 'Country', 'City', 'Attack Type', 'Severity', 'Path', 'Blocked', 'Rule'];
  
  const rows = stats.recentAttacks.map(a => [
    a.id,
    new Date(a.timestamp).toISOString(),
    a.ip,
    a.country || '',
    a.city || '',
    a.attackType,
    a.severity,
    a.path,
    a.blocked ? 'Yes' : 'No',
    a.triggeredRule || '',
  ]);

  return [headers, ...rows].map(row => row.join(',')).join('\n');
}

export function exportToJSON(timeRange?: TimeRange): string {
  const stats = getStats(timeRange);
  return JSON.stringify(stats, null, 2);
}

// ============================================
// Dashboard HTML Generator
// ============================================

export function generateDashboardHTML(baseUrl: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Trap Security Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { background: #0f172a; color: #e2e8f0; }
    .card { background: #1e293b; border-radius: 12px; }
    .stat-card { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); }
  </style>
</head>
<body class="min-h-screen p-6">
  <div class="max-w-7xl mx-auto">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-white flex items-center gap-3">
        🪤 Trap Security Dashboard
      </h1>
      <p class="text-slate-400 mt-2">Real-time attack monitoring and analytics</p>
    </header>

    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div class="stat-card p-6 rounded-xl">
        <div class="text-slate-400 text-sm">Total Attacks</div>
        <div class="text-3xl font-bold text-white mt-1" id="totalAttacks">-</div>
      </div>
      <div class="stat-card p-6 rounded-xl">
        <div class="text-slate-400 text-sm">Blocked</div>
        <div class="text-3xl font-bold text-green-400 mt-1" id="blockedAttacks">-</div>
      </div>
      <div class="stat-card p-6 rounded-xl">
        <div class="text-slate-400 text-sm">Unique IPs</div>
        <div class="text-3xl font-bold text-blue-400 mt-1" id="uniqueIPs">-</div>
      </div>
      <div class="stat-card p-6 rounded-xl">
        <div class="text-slate-400 text-sm">Block Rate</div>
        <div class="text-3xl font-bold text-yellow-400 mt-1" id="blockRate">-</div>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <div class="card p-6">
        <h3 class="text-lg font-semibold mb-4">Attacks Timeline (24h)</h3>
        <canvas id="timelineChart"></canvas>
      </div>
      <div class="card p-6">
        <h3 class="text-lg font-semibold mb-4">Attacks by Type</h3>
        <canvas id="typeChart"></canvas>
      </div>
    </div>

    <!-- Tables Row -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <div class="card p-6">
        <h3 class="text-lg font-semibold mb-4">Top Attackers</h3>
        <table class="w-full">
          <thead>
            <tr class="text-slate-400 text-sm">
              <th class="text-left pb-3">IP</th>
              <th class="text-left pb-3">Country</th>
              <th class="text-right pb-3">Attacks</th>
            </tr>
          </thead>
          <tbody id="topAttackers"></tbody>
        </table>
      </div>
      <div class="card p-6">
        <h3 class="text-lg font-semibold mb-4">Top Targeted Paths</h3>
        <table class="w-full">
          <thead>
            <tr class="text-slate-400 text-sm">
              <th class="text-left pb-3">Path</th>
              <th class="text-right pb-3">Hits</th>
            </tr>
          </thead>
          <tbody id="topPaths"></tbody>
        </table>
      </div>
    </div>

    <!-- Recent Attacks -->
    <div class="card p-6">
      <h3 class="text-lg font-semibold mb-4">Recent Attacks</h3>
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead>
            <tr class="text-slate-400 text-sm">
              <th class="text-left pb-3">Time</th>
              <th class="text-left pb-3">IP</th>
              <th class="text-left pb-3">Type</th>
              <th class="text-left pb-3">Severity</th>
              <th class="text-left pb-3">Path</th>
              <th class="text-left pb-3">Status</th>
            </tr>
          </thead>
          <tbody id="recentAttacks"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const API_URL = '${baseUrl}/api/trap/stats';
    
    const severityColors = {
      LOW: '#22c55e',
      MEDIUM: '#eab308',
      HIGH: '#f97316',
      CRITICAL: '#ef4444',
    };

    async function fetchStats() {
      try {
        const res = await fetch(API_URL);
        const stats = await res.json();
        updateDashboard(stats);
      } catch (e) {
        console.error('Failed to fetch stats:', e);
      }
    }

    function updateDashboard(stats) {
      // Update stat cards
      document.getElementById('totalAttacks').textContent = stats.totalAttacks.toLocaleString();
      document.getElementById('blockedAttacks').textContent = stats.blockedAttacks.toLocaleString();
      document.getElementById('uniqueIPs').textContent = stats.uniqueIPs.toLocaleString();
      document.getElementById('blockRate').textContent = 
        stats.totalAttacks > 0 
          ? Math.round(stats.blockedAttacks / stats.totalAttacks * 100) + '%'
          : '0%';

      // Update timeline chart
      updateTimelineChart(stats.timeline);

      // Update type chart
      updateTypeChart(stats.attacksByType);

      // Update top attackers
      updateTopAttackers(stats.topAttackers);

      // Update top paths
      updateTopPaths(stats.topPaths);

      // Update recent attacks
      updateRecentAttacks(stats.recentAttacks);
    }

    let timelineChart, typeChart;

    function updateTimelineChart(timeline) {
      const ctx = document.getElementById('timelineChart').getContext('2d');
      const labels = timeline.map(t => new Date(t.timestamp).toLocaleTimeString());
      const data = timeline.map(t => t.count);

      if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = data;
        timelineChart.update();
      } else {
        timelineChart = new Chart(ctx, {
          type: 'line',
          data: {
            labels,
            datasets: [{
              label: 'Attacks',
              data,
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              fill: true,
              tension: 0.4,
            }]
          },
          options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
              x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
              y: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
            }
          }
        });
      }
    }

    function updateTypeChart(attacksByType) {
      const ctx = document.getElementById('typeChart').getContext('2d');
      const labels = Object.keys(attacksByType);
      const data = Object.values(attacksByType);
      const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'];

      if (typeChart) {
        typeChart.data.labels = labels;
        typeChart.data.datasets[0].data = data;
        typeChart.update();
      } else {
        typeChart = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels,
            datasets: [{
              data,
              backgroundColor: colors,
            }]
          },
          options: {
            responsive: true,
            plugins: {
              legend: { position: 'right', labels: { color: '#e2e8f0' } }
            }
          }
        });
      }
    }

    function updateTopAttackers(attackers) {
      const tbody = document.getElementById('topAttackers');
      tbody.innerHTML = attackers.map(a => \`
        <tr class="border-t border-slate-700">
          <td class="py-2 font-mono text-sm">\${a.ip}</td>
          <td class="py-2">\${a.country || '-'}</td>
          <td class="py-2 text-right font-semibold">\${a.count}</td>
        </tr>
      \`).join('');
    }

    function updateTopPaths(paths) {
      const tbody = document.getElementById('topPaths');
      tbody.innerHTML = paths.map(p => \`
        <tr class="border-t border-slate-700">
          <td class="py-2 font-mono text-sm truncate max-w-xs">\${p.path}</td>
          <td class="py-2 text-right font-semibold">\${p.count}</td>
        </tr>
      \`).join('');
    }

    function updateRecentAttacks(attacks) {
      const tbody = document.getElementById('recentAttacks');
      tbody.innerHTML = attacks.slice(0, 20).map(a => \`
        <tr class="border-t border-slate-700">
          <td class="py-2 text-sm">\${new Date(a.timestamp).toLocaleString()}</td>
          <td class="py-2 font-mono text-sm">\${a.ip}</td>
          <td class="py-2 text-sm">\${a.attackType}</td>
          <td class="py-2">
            <span class="px-2 py-1 rounded text-xs" style="background: \${severityColors[a.severity]}20; color: \${severityColors[a.severity]}">
              \${a.severity}
            </span>
          </td>
          <td class="py-2 font-mono text-sm truncate max-w-xs">\${a.path}</td>
          <td class="py-2">
            \${a.blocked 
              ? '<span class="text-green-400">✓ Blocked</span>' 
              : '<span class="text-slate-400">Logged</span>'}
          </td>
        </tr>
      \`).join('');
    }

    // Initial fetch and refresh every 30 seconds
    fetchStats();
    setInterval(fetchStats, 30000);
  </script>
</body>
</html>`;
}

export default {
  recordAttack,
  getStats,
  getAttack,
  getAttacksByIP,
  getAttacksByType,
  getRecentAttacks,
  exportToCSV,
  exportToJSON,
  generateDashboardHTML,
};

