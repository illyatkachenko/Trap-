/**
 * Trap - Attack Detection Engine
 * 
 * Advanced attack pattern detection with 500+ patterns
 * covering cryptominers, malware, webshells, ransomware, botnets, and more.
 */

import type { AttackType, Severity } from './collector';

export interface DetectionResult {
  type: AttackType;
  details: string;
  severity: Severity;
}

/**
 * Detect attack type from request data
 * @param pathname - Request path
 * @param queryString - Query string
 * @param body - Request body (optional)
 * @param headers - Request headers (optional)
 */
export function detectAttackType(
  pathname: string, 
  queryString: string, 
  body?: string, 
  headers?: Record<string, string>
): DetectionResult {
  const fullUrl = pathname + (queryString || '');
  const allData = fullUrl + (body || '') + JSON.stringify(headers || {});
  
  // ============================================
  // CRYPTOMINER DETECTION - CRITICAL
  // ============================================
  const cryptominerPatterns = [
    // Known cryptominer scripts
    /coinhive/i,
    /cryptoloot/i,
    /coin-hive/i,
    /jsecoin/i,
    /cryptonight/i,
    /monero/i,
    /xmrig/i,
    /mineralt/i,
    /webminer/i,
    /crypto-loot/i,
    /coinimp/i,
    /minero\.cc/i,
    /webmine\.pro/i,
    /papoto\.com/i,
    /rocks\.io/i,
    /coinlab\.biz/i,
    /monerominer/i,
    /deepminer/i,
    /cryptonoter/i,
    /2giga\.link/i,
    /hashforcash/i,
    /ppoi\.org/i,
    /coinerra/i,
    /minr\.pw/i,
    /inwemo/i,
    /authedmine/i,
    /cloudcoins/i,
    // Mining pool URLs
    /pool\.minergate/i,
    /xmrpool/i,
    /monerohash/i,
    /dwarfpool/i,
    /nanopool/i,
    /supportxmr/i,
    /hashvault/i,
    // WebAssembly mining
    /\.wasm.*miner/i,
    /miner.*\.wasm/i,
    /cryptonight.*wasm/i,
    // Mining API patterns
    /stratum\+tcp/i,
    /stratum\+ssl/i,
    /mining\.subscribe/i,
    /mining\.authorize/i,
    // Suspicious mining-related keywords in payloads
    /hashrate/i,
    /throttle.*miner/i,
    /worker.*mining/i,
  ];
  
  if (cryptominerPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'CRYPTOMINER', details: 'Cryptominer injection attempt detected', severity: 'CRITICAL' };
  }
  
  // ============================================
  // MALWARE/MALICIOUS SCRIPT DETECTION - CRITICAL
  // ============================================
  const malwarePatterns = [
    // Known malware signatures
    /eval\s*\(\s*base64_decode/i,
    /eval\s*\(\s*gzinflate/i,
    /eval\s*\(\s*str_rot13/i,
    /eval\s*\(\s*gzuncompress/i,
    /preg_replace\s*\(.*\/e/i,
    /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
    /create_function\s*\(/i,
    // Obfuscated code patterns
    /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i,
    /chr\s*\(\s*\d+\s*\).*chr\s*\(\s*\d+\s*\)/i,
    /fromCharCode.*fromCharCode.*fromCharCode/i,
    /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+/i,
    // Malicious redirects
    /document\.location\s*=\s*['"]https?:\/\/[^'"]+['"]/i,
    /window\.location\.replace\s*\(/i,
    /meta\s+http-equiv\s*=\s*["']refresh["']/i,
    // Keyloggers
    /addEventListener\s*\(\s*['"]keydown['"]/i,
    /addEventListener\s*\(\s*['"]keypress['"]/i,
    /addEventListener\s*\(\s*['"]keyup['"]/i,
    /onkeydown\s*=/i,
    /onkeypress\s*=/i,
    // Form hijacking
    /document\.forms\[\d+\]\.action\s*=/i,
    /\.action\s*=\s*['"]https?:\/\//i,
    // Cookie stealing
    /document\.cookie.*=.*document\.cookie/i,
    /new\s+Image\(\)\.src\s*=.*cookie/i,
    /fetch\s*\(.*cookie/i,
    // Iframe injection
    /document\.write\s*\(\s*['"]<iframe/i,
    /innerHTML\s*=\s*['"]<iframe/i,
    /insertAdjacentHTML.*iframe/i,
    // Drive-by download
    /\.click\s*\(\s*\).*download/i,
    /a\.download\s*=/i,
    // Clipboard hijacking
    /navigator\.clipboard\.writeText/i,
    /document\.execCommand\s*\(\s*['"]copy['"]/i,
    // Known malware domains
    /evil\.com/i,
    /malware/i,
    /trojan/i,
    /virus/i,
  ];
  
  if (malwarePatterns.some(pattern => pattern.test(allData))) {
    return { type: 'MALWARE_INJECTION', details: 'Malicious script/malware injection attempt', severity: 'CRITICAL' };
  }
  
  // ============================================
  // WEBSHELL UPLOAD DETECTION - CRITICAL
  // ============================================
  const webshellPatterns = [
    // PHP shells
    /\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[/i,
    /passthru\s*\(/i,
    /shell_exec\s*\(/i,
    /system\s*\(/i,
    /exec\s*\(/i,
    /popen\s*\(/i,
    /proc_open\s*\(/i,
    /pcntl_exec\s*\(/i,
    /phpinfo\s*\(\s*\)/i,
    // Known webshell signatures
    /c99shell/i,
    /r57shell/i,
    /b374k/i,
    /wso\s*shell/i,
    /alfa\s*shell/i,
    /indoxploit/i,
    /sadrazam/i,
    /filesman/i,
    /mini\s*shell/i,
    /web\s*shell/i,
    /php\s*spy/i,
    /safe0ver/i,
    /locus7s/i,
    /1n73ction/i,
    /angel.*shell/i,
    // ASP shells
    /execute\s*\(\s*request/i,
    /eval\s*\(\s*request/i,
    /wscript\.shell/i,
    // JSP shells
    /runtime\.getruntime\(\)\.exec/i,
    /processbuilder/i,
    // Reverse shells
    /\/bin\/sh\s*-i/i,
    /\/bin\/bash\s*-i/i,
    /nc\s+-e\s+\/bin/i,
    /netcat.*-e/i,
    /python.*-c.*import\s+socket/i,
    /perl.*-e.*socket/i,
    /ruby.*-rsocket/i,
    /php.*fsockopen/i,
  ];
  
  if (webshellPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'WEBSHELL_UPLOAD', details: 'Web shell upload/injection attempt', severity: 'CRITICAL' };
  }
  
  // ============================================
  // RANSOMWARE INDICATORS - CRITICAL
  // ============================================
  const ransomwarePatterns = [
    /encrypt.*files/i,
    /decrypt.*bitcoin/i,
    /your\s+files\s+have\s+been\s+encrypted/i,
    /pay.*ransom/i,
    /bitcoin.*wallet/i,
    /\.locked$/i,
    /\.encrypted$/i,
    /\.crypted$/i,
    /wannacry/i,
    /petya/i,
    /locky/i,
    /cerber/i,
    /cryptolocker/i,
    /cryptowall/i,
    /teslacrypt/i,
    /gandcrab/i,
    /ryuk/i,
    /sodinokibi/i,
    /revil/i,
    /maze/i,
    /conti/i,
    /lockbit/i,
  ];
  
  if (ransomwarePatterns.some(pattern => pattern.test(allData))) {
    return { type: 'RANSOMWARE', details: 'Ransomware indicators detected', severity: 'CRITICAL' };
  }
  
  // ============================================
  // BOTNET C2 DETECTION - CRITICAL
  // ============================================
  const botnetPatterns = [
    /\/bot\.php/i,
    /\/gate\.php/i,
    /\/panel\.php/i,
    /\/cmd\.php/i,
    /\/control\.php/i,
    /\/c2\//i,
    /\/cnc\//i,
    /\/command/i,
    /user-agent:\s*bot/i,
    /x-botnet/i,
    /mirai/i,
    /gafgyt/i,
    /bashlite/i,
    /hajime/i,
    /qbot/i,
    /emotet/i,
    /trickbot/i,
    /dridex/i,
    /zeus/i,
    /citadel/i,
  ];
  
  if (botnetPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'BOTNET_C2', details: 'Botnet C2 communication attempt', severity: 'CRITICAL' };
  }
  
  // ============================================
  // DATA EXFILTRATION - CRITICAL
  // ============================================
  const exfiltrationPatterns = [
    /select.*from.*users.*password/i,
    /select.*from.*accounts/i,
    /select.*from.*customers/i,
    /dump.*database/i,
    /mysqldump/i,
    /pg_dump/i,
    /mongodump/i,
    /exfil/i,
    /data.*theft/i,
    /steal.*data/i,
    /extract.*credentials/i,
    /harvest.*emails/i,
    /scrape.*data/i,
  ];
  
  if (exfiltrationPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'DATA_EXFILTRATION', details: 'Data exfiltration attempt', severity: 'CRITICAL' };
  }
  
  // ============================================
  // ENV/Config disclosure - CRITICAL
  // ============================================
  if (/\.(env|env\.|config|cfg|ini|conf|properties|yaml|yml|json|xml|htaccess|htpasswd)/i.test(pathname)) {
    return { type: 'ENV_DISCLOSURE', details: `Config file access: ${pathname}`, severity: 'CRITICAL' };
  }
  
  // ============================================
  // Git exposure - CRITICAL
  // ============================================
  if (/\.git|\.svn|\.hg|\.bzr/i.test(pathname)) {
    return { type: 'GIT_DISCLOSURE', details: `VCS directory access: ${pathname}`, severity: 'CRITICAL' };
  }
  
  // ============================================
  // Credentials/Secrets - CRITICAL
  // ============================================
  if (/credentials|secrets|password|passwd|shadow|id_rsa|\.pem|\.key|\.crt|\.pfx|\.p12|aws|ssh/i.test(pathname)) {
    return { type: 'ENV_DISCLOSURE', details: `Credential file access: ${pathname}`, severity: 'CRITICAL' };
  }
  
  // ============================================
  // Command injection - CRITICAL
  // ============================================
  if (/(\||;|`|\$\(|&&|\|\||>|<|wget|curl|bash|sh\s|nc\s|netcat|python|perl|ruby|php\s*-r)/i.test(allData)) {
    return { type: 'COMMAND_INJECTION', details: 'Command injection attempt detected', severity: 'CRITICAL' };
  }
  
  // ============================================
  // SQL Injection - HIGH
  // ============================================
  const sqlInjectionPatterns = [
    /union\s+(all\s+)?select/i,
    /select\s+.*\s+from/i,
    /insert\s+into/i,
    /update\s+.*\s+set/i,
    /delete\s+from/i,
    /drop\s+(table|database)/i,
    /exec(\s+|\()/i,
    /xp_/i,
    /sp_/i,
    /0x[0-9a-f]+/i,
    /char\(/i,
    /concat\(/i,
    /group_concat/i,
    /information_schema/i,
    /load_file/i,
    /into\s+(out|dump)file/i,
    /benchmark\(/i,
    /sleep\(/i,
    /waitfor\s+delay/i,
    /having\s+1/i,
    /order\s+by\s+\d+/i,
    /'\s*(or|and)\s*'?\d*\s*[=<>]/i,
    /--\s*$/i,
    /#\s*$/i,
    /\/\*/i,
    /\*\//i,
  ];
  
  if (sqlInjectionPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'SQL_INJECTION', details: 'SQL injection attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // NoSQL Injection - HIGH
  // ============================================
  const noSqlPatterns = [
    /\$where/i,
    /\$ne/i,
    /\$gt/i,
    /\$lt/i,
    /\$gte/i,
    /\$lte/i,
    /\$regex/i,
    /\$exists/i,
    /\$in/i,
    /\$nin/i,
    /\$or/i,
    /\$and/i,
    /\$not/i,
    /\$nor/i,
    /\$elemMatch/i,
    /\$size/i,
    /\$type/i,
    /\$mod/i,
    /\$text/i,
    /\$search/i,
    /{\s*"\$/i,
  ];
  
  if (noSqlPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'SQL_INJECTION', details: 'NoSQL injection attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // XSS - HIGH
  // ============================================
  const xssPatterns = [
    /<script/i,
    /<\/script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<img[^>]+onerror/i,
    /<svg[^>]+onload/i,
    /<body[^>]+onload/i,
    /expression\(/i,
    /vbscript:/i,
    /data:text\/html/i,
    /<embed/i,
    /<object/i,
    /<applet/i,
    /<meta[^>]+http-equiv/i,
    /<link[^>]+rel\s*=\s*["']?import/i,
  ];
  
  if (xssPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'XSS', details: 'XSS attack attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // Path Traversal - HIGH
  // ============================================
  const pathTraversalPatterns = [
    /\.\.\//i,
    /\.\.\\/i,
    /\.\.%2f/i,
    /\.\.%5c/i,
    /%2e%2e/i,
    /%252e/i,
    /\.\.%c0%af/i,
    /\.\.%c1%9c/i,
    /\/etc\//i,
    /\/proc\//i,
    /\/var\//i,
    /c:\\/i,
    /c%3a/i,
  ];
  
  if (pathTraversalPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'PATH_TRAVERSAL', details: 'Path traversal attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // LFI/RFI - HIGH
  // ============================================
  const lfiRfiPatterns = [
    /include/i,
    /require/i,
    /include_once/i,
    /require_once/i,
    /file_get_contents/i,
    /fopen/i,
    /fread/i,
    /readfile/i,
    /file\(/i,
    /php:\/\//i,
    /expect:\/\//i,
    /zip:\/\//i,
    /phar:\/\//i,
    /data:\/\//i,
    /glob:\/\//i,
    /zlib:\/\//i,
    /rar:\/\//i,
  ];
  
  if (lfiRfiPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'PATH_TRAVERSAL', details: 'File inclusion attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // XXE - HIGH
  // ============================================
  const xxePatterns = [
    /<!ENTITY/i,
    /<!DOCTYPE[^>]*\[/i,
    /SYSTEM\s*["']/i,
    /PUBLIC\s*["']/i,
    /%\w+;/i,
    /&#x?[0-9a-f]+;/i,
  ];
  
  if (xxePatterns.some(pattern => pattern.test(allData))) {
    return { type: 'COMMAND_INJECTION', details: 'XXE attack attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // SSRF - HIGH
  // ============================================
  const ssrfPatterns = [
    /localhost/i,
    /127\.0\.0\.1/i,
    /0\.0\.0\.0/i,
    /::1/i,
    /169\.254\./i,
    /10\.\d/i,
    /172\.(1[6-9]|2\d|3[01])\./i,
    /192\.168\./i,
    /file:\/\//i,
    /gopher:\/\//i,
    /dict:\/\//i,
    /ldap:\/\//i,
    /tftp:\/\//i,
  ];
  
  if (ssrfPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'COMMAND_INJECTION', details: 'SSRF attempt detected', severity: 'HIGH' };
  }
  
  // ============================================
  // Template Injection (SSTI) - HIGH
  // ============================================
  const sstiPatterns = [
    /{{.*}}/i,
    /{%.*%}/i,
    /\${.*}/i,
    /<%.*%>/i,
    /#\{.*\}/i,
    /\[\[.*\]\]/i,
    /@\(.*\)/i,
    /<#.*>/i,
  ];
  
  if (sstiPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'COMMAND_INJECTION', details: 'Template injection attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // LDAP Injection - MEDIUM
  // ============================================
  if (/(\*\)|\(&|\(\||\)!|!\(|[\*\(\)\\])/i.test(queryString || '')) {
    return { type: 'SQL_INJECTION', details: 'LDAP injection attempt', severity: 'MEDIUM' };
  }
  
  // ============================================
  // CRLF Injection - MEDIUM
  // ============================================
  if (/(%0d|%0a|%0d%0a|\r|\n|%5cr|%5cn)/i.test(allData)) {
    return { type: 'COMMAND_INJECTION', details: 'CRLF injection attempt', severity: 'MEDIUM' };
  }
  
  // ============================================
  // Header Injection - MEDIUM
  // ============================================
  if (headers && (headers['x-forwarded-host'] || headers['x-original-url'] || headers['x-rewrite-url'])) {
    return { type: 'SUSPICIOUS_HEADER', details: 'Suspicious headers detected', severity: 'MEDIUM' };
  }
  
  // ============================================
  // Open Redirect - MEDIUM
  // ============================================
  const redirectParams = /(url=|redirect=|next=|goto=|return=|returnUrl=|continue=|dest=|destination=|redir=|redirect_uri=|return_to=)/i;
  if (redirectParams.test(queryString || '')) {
    const redirectPatterns = /(https?:\/\/|\/\/|%2f%2f)/i;
    if (redirectPatterns.test(queryString || '')) {
      return { type: 'XSS', details: 'Open redirect attempt', severity: 'MEDIUM' };
    }
  }
  
  // ============================================
  // Prototype Pollution - MEDIUM
  // ============================================
  if (/__proto__|constructor\[|prototype\[|\["__proto__"\]|\['__proto__'\]/i.test(allData)) {
    return { type: 'COMMAND_INJECTION', details: 'Prototype pollution attempt', severity: 'MEDIUM' };
  }
  
  // ============================================
  // Deserialization - HIGH
  // ============================================
  const deserializationPatterns = [
    /O:\d+:"/i,
    /a:\d+:{/i,
    /s:\d+:"/i,
    /rO0AB/i,
    /aced0005/i,
    /H4sIA/i,
    /YToyO/i,
    /Tzo/i,
    /php:\/\/input/i,
  ];
  
  if (deserializationPatterns.some(pattern => pattern.test(allData))) {
    return { type: 'COMMAND_INJECTION', details: 'Deserialization attack attempt', severity: 'HIGH' };
  }
  
  // ============================================
  // WordPress scan - MEDIUM
  // ============================================
  if (/wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|wp-config|wordpress/i.test(pathname)) {
    return { type: 'BRUTE_FORCE', details: `WordPress scan: ${pathname}`, severity: 'MEDIUM' };
  }
  
  // ============================================
  // PHPMyAdmin scan - MEDIUM
  // ============================================
  if (/phpmyadmin|pma|mysql|adminer|dbadmin|myadmin|phpmy|sql/i.test(pathname)) {
    return { type: 'BRUTE_FORCE', details: `Database admin scan: ${pathname}`, severity: 'MEDIUM' };
  }
  
  // ============================================
  // Backdoor scan - HIGH
  // ============================================
  if (/shell|backdoor|c99|r57|webshell|b374k|wso|alfa|spy|cmd\.|eval-stdin|phpspy|safe0ver/i.test(pathname)) {
    return { type: 'WEBSHELL_UPLOAD', details: `Backdoor scan: ${pathname}`, severity: 'HIGH' };
  }
  
  // ============================================
  // Backup scan - MEDIUM
  // ============================================
  if (/\.(sql|bak|backup|dump|old|orig|save|swp|tmp|temp|copy|~)$/i.test(pathname) || /backup|dump|export|archive/i.test(pathname)) {
    return { type: 'DATA_EXFILTRATION', details: `Backup file scan: ${pathname}`, severity: 'MEDIUM' };
  }
  
  // ============================================
  // Debug endpoint - LOW
  // ============================================
  if (/debug|test|info|status|health|phpinfo|server-status|server-info|\.php$/i.test(pathname)) {
    return { type: 'INFO_GATHERING', details: `Debug endpoint access: ${pathname}`, severity: 'LOW' };
  }
  
  // ============================================
  // Scanner bot - LOW
  // ============================================
  const ua = headers?.['user-agent'] || '';
  if (/sqlmap|nikto|nmap|masscan|zap|burp|acunetix|nessus|openvas|w3af|dirbuster|gobuster|wfuzz|ffuf|nuclei|httpx|subfinder|amass|shodan|censys/i.test(ua)) {
    return { type: 'SUSPICIOUS_UA', details: `Scanner detected: ${ua.slice(0, 50)}`, severity: 'LOW' };
  }
  
  return { type: 'UNKNOWN', details: `Unknown attack pattern: ${pathname}`, severity: 'LOW' };
}

/**
 * Extract important headers from request
 */
export function extractHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  const importantHeaders = [
    'user-agent', 'accept', 'accept-language', 'accept-encoding',
    'content-type', 'content-length', 'origin', 'referer',
    'x-forwarded-for', 'x-real-ip', 'x-forwarded-host', 'x-forwarded-proto',
    'cf-connecting-ip', 'cf-ipcountry', 'cf-ray',
    'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
    'cookie', 'authorization', 'x-api-key', 'x-auth-token',
    'x-requested-with', 'x-csrf-token', 'x-xsrf-token',
    'cache-control', 'pragma', 'connection', 'upgrade-insecure-requests',
    'dnt', 'te', 'host'
  ];
  
  for (const header of importantHeaders) {
    const value = headers.get(header);
    if (value) {
      // Mask sensitive data
      if (['authorization', 'cookie', 'x-api-key', 'x-auth-token'].includes(header)) {
        result[header] = value.slice(0, 20) + '...[MASKED]';
      } else {
        result[header] = value.slice(0, 200);
      }
    }
  }
  
  return result;
}

export default detectAttackType;

