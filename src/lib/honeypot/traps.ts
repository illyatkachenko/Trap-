/**
 * Trap - Honeypot Trap Definitions
 * 
 * Comprehensive trap patterns covering 195+ attack vectors.
 * Based on real-world attack data and security research.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import type { AttackType, Severity } from './collector';

// ============================================
// Types
// ============================================

export interface HoneypotTrap {
  pattern: RegExp;
  trapType: 'env' | 'creds' | 'fingerprint';
  attackType: AttackType;
  severity: Severity;
  description: string;
}

// ============================================
// Comprehensive Trap Patterns (195+)
// ============================================

export const TRAP_PATTERNS: HoneypotTrap[] = [
  // ============ ENV/CONFIG FILES ============
  { pattern: /^\/.env($|\.)/, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Environment file' },
  { pattern: /^\/\.env\.(local|production|development|staging|test|backup|bak|old|save|orig|example|sample)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Env variant' },
  { pattern: /^\/config\.(php|json|yml|yaml|xml|ini|js|ts|env)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Config file' },
  { pattern: /^\/settings\.(php|json|yml|yaml|xml|ini|js)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Settings file' },
  { pattern: /^\/database\.(yml|yaml|json|php|xml)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Database config' },
  { pattern: /^\/application\.(yml|yaml|properties)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Application config' },
  { pattern: /^\/\.htaccess$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Apache config' },
  { pattern: /^\/\.htpasswd$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Apache passwords' },
  { pattern: /^\/web\.config$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'IIS config' },
  { pattern: /^\/app\.config$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'App config' },
  { pattern: /^\/docker-compose\.(yml|yaml)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Docker compose' },
  { pattern: /^\/Dockerfile$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'MEDIUM', description: 'Dockerfile' },
  { pattern: /^\/\.dockerignore$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Docker ignore' },
  { pattern: /^\/kubernetes\.(yml|yaml)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Kubernetes config' },
  { pattern: /^\/k8s\.(yml|yaml)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'K8s config' },
  { pattern: /^\/\.kube\/config$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Kube config' },
  
  // ============ GIT/VCS ============
  { pattern: /^\/\.git(\/.*)?$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'CRITICAL', description: 'Git directory' },
  { pattern: /^\/\.gitconfig$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'HIGH', description: 'Git config' },
  { pattern: /^\/\.gitignore$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Git ignore' },
  { pattern: /^\/\.svn(\/.*)?$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'CRITICAL', description: 'SVN directory' },
  { pattern: /^\/\.hg(\/.*)?$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'CRITICAL', description: 'Mercurial directory' },
  { pattern: /^\/\.bzr(\/.*)?$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'CRITICAL', description: 'Bazaar directory' },
  { pattern: /^\/CVS(\/.*)?$/i, trapType: 'env', attackType: 'GIT_DISCLOSURE', severity: 'CRITICAL', description: 'CVS directory' },
  
  // ============ CREDENTIALS/SECRETS ============
  { pattern: /^\/secrets?\.(json|yml|yaml|xml|env)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Secrets file' },
  { pattern: /^\/credentials?\.(json|yml|yaml|xml|env)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Credentials file' },
  { pattern: /^\/passwords?\.(txt|json|yml|xml)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Passwords file' },
  { pattern: /^\/\.aws(\/.*)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'AWS credentials' },
  { pattern: /^\/\.ssh(\/.*)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'SSH keys' },
  { pattern: /^\/(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'SSH key' },
  { pattern: /^\/.+\.(pem|key|crt|cer|pfx|p12)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Certificate/Key' },
  { pattern: /^\/\.npmrc$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'NPM config' },
  { pattern: /^\/\.yarnrc$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Yarn config' },
  { pattern: /^\/\.pypirc$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'PyPI config' },
  { pattern: /^\/\.netrc$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Netrc file' },
  { pattern: /^\/\.pgpass$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'PostgreSQL passwords' },
  { pattern: /^\/\.my\.cnf$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'MySQL config' },
  { pattern: /^\/\.bash_history$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Bash history' },
  { pattern: /^\/\.zsh_history$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Zsh history' },
  
  // ============ WORDPRESS ============
  { pattern: /^\/wp-admin(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'WordPress admin' },
  { pattern: /^\/wp-login\.php$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'WordPress login' },
  { pattern: /^\/wp-config\.php(\.bak|\.old|\.save|\.orig|\.txt)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'WordPress config' },
  { pattern: /^\/wp-content(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'WordPress content' },
  { pattern: /^\/wp-includes(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'WordPress includes' },
  { pattern: /^\/xmlrpc\.php$/i, trapType: 'env', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'WordPress XMLRPC' },
  { pattern: /^\/wp-cron\.php$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'WordPress cron' },
  { pattern: /^\/wordpress(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'WordPress directory' },
  
  // ============ DATABASE ADMIN ============
  { pattern: /^\/phpmyadmin(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'phpMyAdmin' },
  { pattern: /^\/pma(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'phpMyAdmin (pma)' },
  { pattern: /^\/mysql(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'MySQL admin' },
  { pattern: /^\/adminer(\.php)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Adminer' },
  { pattern: /^\/dbadmin(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'DB Admin' },
  { pattern: /^\/myadmin(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'MyAdmin' },
  { pattern: /^\/phpmy(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'phpMy' },
  { pattern: /^\/sql(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'SQL admin' },
  { pattern: /^\/pgadmin(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'pgAdmin' },
  { pattern: /^\/mongodb(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'MongoDB admin' },
  { pattern: /^\/redis(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Redis admin' },
  
  // ============ CMS ADMIN PANELS ============
  { pattern: /^\/admin(\.php)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Admin panel' },
  { pattern: /^\/administrator(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Joomla admin' },
  { pattern: /^\/admin_area(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Admin area' },
  { pattern: /^\/admincp(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Admin CP' },
  { pattern: /^\/modcp(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'MEDIUM', description: 'Mod CP' },
  { pattern: /^\/cpanel(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'cPanel' },
  { pattern: /^\/controlpanel(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Control Panel' },
  { pattern: /^\/manager(\/.*)?$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Manager' },
  { pattern: /^\/user\/login$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'MEDIUM', description: 'User login' },
  { pattern: /^\/login\.php$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'HIGH', description: 'Login page' },
  { pattern: /^\/signin$/i, trapType: 'creds', attackType: 'BRUTE_FORCE', severity: 'MEDIUM', description: 'Sign in' },
  
  // ============ BACKUP FILES ============
  { pattern: /\.(sql|sql\.gz|sql\.zip|sql\.bz2|sql\.tar|sql\.tar\.gz)$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'CRITICAL', description: 'SQL backup' },
  { pattern: /\.(bak|backup|old|orig|save|swp|tmp|temp|copy)$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'HIGH', description: 'Backup file' },
  { pattern: /^\/backup(s)?(\/.*)?$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'CRITICAL', description: 'Backup directory' },
  { pattern: /^\/dump(s)?(\/.*)?$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'CRITICAL', description: 'Dump directory' },
  { pattern: /^\/export(s)?(\/.*)?$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'HIGH', description: 'Export directory' },
  { pattern: /^\/archive(s)?(\/.*)?$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'HIGH', description: 'Archive directory' },
  { pattern: /^\/db(\/.*)?$/i, trapType: 'env', attackType: 'DATA_EXFILTRATION', severity: 'HIGH', description: 'Database directory' },
  { pattern: /^\/data(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Data directory' },
  
  // ============ DEBUG/INFO ENDPOINTS ============
  { pattern: /^\/debug(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Debug endpoint' },
  { pattern: /^\/test(\.php)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Test endpoint' },
  { pattern: /^\/info(\.php)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Info endpoint' },
  { pattern: /^\/phpinfo(\.php)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'PHP info' },
  { pattern: /^\/server-status$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Server status' },
  { pattern: /^\/server-info$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Server info' },
  { pattern: /^\/_debug(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Debug endpoint' },
  { pattern: /^\/_profiler(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Profiler' },
  { pattern: /^\/trace(\.axd)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Trace' },
  { pattern: /^\/elmah(\.axd)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'ELMAH' },
  { pattern: /^\/actuator(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'HIGH', description: 'Spring Actuator' },
  { pattern: /^\/metrics$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Metrics endpoint' },
  { pattern: /^\/swagger(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Swagger docs' },
  { pattern: /^\/api-docs(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'API docs' },
  { pattern: /^\/graphql$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'GraphQL endpoint' },
  { pattern: /^\/graphiql$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'GraphiQL' },
  
  // ============ SHELL/BACKDOOR ============
  { pattern: /shell/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'Shell access' },
  { pattern: /backdoor/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'Backdoor' },
  { pattern: /c99/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'C99 shell' },
  { pattern: /r57/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'R57 shell' },
  { pattern: /webshell/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'Webshell' },
  { pattern: /b374k/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'B374K shell' },
  { pattern: /wso/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'WSO shell' },
  { pattern: /alfa/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'Alfa shell' },
  { pattern: /phpspy/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'PHP spy' },
  { pattern: /cmd\.(php|asp|aspx|jsp)$/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'CMD shell' },
  { pattern: /eval-stdin/i, trapType: 'env', attackType: 'WEBSHELL_UPLOAD', severity: 'CRITICAL', description: 'Eval stdin' },
  
  // ============ PHP FILES (potential exploits) ============
  { pattern: /\.php$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'PHP file' },
  { pattern: /\.php\d$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'PHP file (versioned)' },
  { pattern: /\.phtml$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'PHTML file' },
  { pattern: /\.php\.(bak|old|orig|save|txt)$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'PHP backup' },
  
  // ============ ASP/ASPX FILES ============
  { pattern: /\.asp$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'ASP file' },
  { pattern: /\.aspx$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'ASPX file' },
  
  // ============ JSP FILES ============
  { pattern: /\.jsp$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'JSP file' },
  { pattern: /\.jspx$/i, trapType: 'creds', attackType: 'WEBSHELL_UPLOAD', severity: 'HIGH', description: 'JSPX file' },
  
  // ============ CGI FILES ============
  { pattern: /\.cgi$/i, trapType: 'creds', attackType: 'COMMAND_INJECTION', severity: 'HIGH', description: 'CGI file' },
  { pattern: /^\/cgi-bin(\/.*)?$/i, trapType: 'creds', attackType: 'COMMAND_INJECTION', severity: 'HIGH', description: 'CGI-bin' },
  
  // ============ LOG FILES ============
  { pattern: /\.(log|logs)$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Log file' },
  { pattern: /^\/logs?(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Logs directory' },
  { pattern: /^\/var\/log(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'HIGH', description: 'Var log' },
  { pattern: /error\.log$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Error log' },
  { pattern: /access\.log$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'Access log' },
  { pattern: /debug\.log$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'HIGH', description: 'Debug log' },
  
  // ============ CLOUD/INFRA ============
  { pattern: /^\/\.terraform(\/.*)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Terraform state' },
  { pattern: /^\/terraform\.tfstate$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Terraform state file' },
  { pattern: /^\/\.circleci(\/.*)?$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'CircleCI config' },
  { pattern: /^\/\.github(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'MEDIUM', description: 'GitHub config' },
  { pattern: /^\/\.gitlab-ci\.yml$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'GitLab CI' },
  { pattern: /^\/Jenkinsfile$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Jenkinsfile' },
  { pattern: /^\/\.travis\.yml$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'HIGH', description: 'Travis CI' },
  
  // ============ PACKAGE MANAGERS ============
  { pattern: /^\/package\.json$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Package.json' },
  { pattern: /^\/package-lock\.json$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Package lock' },
  { pattern: /^\/yarn\.lock$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Yarn lock' },
  { pattern: /^\/composer\.json$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Composer.json' },
  { pattern: /^\/composer\.lock$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Composer lock' },
  { pattern: /^\/Gemfile(\.lock)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Gemfile' },
  { pattern: /^\/requirements\.txt$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Python requirements' },
  { pattern: /^\/Pipfile(\.lock)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Pipfile' },
  { pattern: /^\/go\.(mod|sum)$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Go modules' },
  { pattern: /^\/Cargo\.(toml|lock)$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Cargo' },
  
  // ============ MISC SENSITIVE ============
  { pattern: /^\/\.DS_Store$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'DS_Store' },
  { pattern: /^\/Thumbs\.db$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Thumbs.db' },
  { pattern: /^\/\.idea(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'IntelliJ config' },
  { pattern: /^\/\.vscode(\/.*)?$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'VS Code config' },
  { pattern: /^\/\.editorconfig$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Editor config' },
  { pattern: /^\/\.babelrc$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Babel config' },
  { pattern: /^\/\.eslintrc/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'ESLint config' },
  { pattern: /^\/tsconfig\.json$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'TypeScript config' },
  { pattern: /^\/webpack\.config\.js$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Webpack config' },
  { pattern: /^\/gulpfile\.js$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Gulp config' },
  { pattern: /^\/Gruntfile\.js$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Grunt config' },
  { pattern: /^\/Makefile$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Makefile' },
  { pattern: /^\/\.htdigest$/i, trapType: 'env', attackType: 'ENV_DISCLOSURE', severity: 'CRITICAL', description: 'Apache digest' },
  { pattern: /^\/crossdomain\.xml$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Flash crossdomain' },
  { pattern: /^\/clientaccesspolicy\.xml$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Silverlight policy' },
  
  // ============ PROC/SYSTEM FILES ============
  { pattern: /^\/proc\//i, trapType: 'env', attackType: 'PATH_TRAVERSAL', severity: 'CRITICAL', description: 'Proc filesystem' },
  { pattern: /^\/etc\/(passwd|shadow|hosts|resolv\.conf)/i, trapType: 'env', attackType: 'PATH_TRAVERSAL', severity: 'CRITICAL', description: 'System files' },
  
  // ============ AUTODISCOVER (Exchange) ============
  { pattern: /^\/autodiscover/i, trapType: 'creds', attackType: 'COMMAND_INJECTION', severity: 'HIGH', description: 'Exchange autodiscover' },
  
  // ============ WELL-KNOWN ============
  { pattern: /^\/\.well-known\/security\.txt$/i, trapType: 'env', attackType: 'INFO_GATHERING', severity: 'LOW', description: 'Security.txt' },
];

// ============================================
// Match trap by pathname
// ============================================

export function matchTrap(pathname: string): HoneypotTrap | null {
  for (const trap of TRAP_PATTERNS) {
    if (trap.pattern.test(pathname)) {
      return trap;
    }
  }
  return null;
}

// ============================================
// Middleware function for Next.js
// ============================================

export function honeypotTraps(request: NextRequest, ip: string): NextResponse | null {
  const { pathname } = request.nextUrl;

  const trap = matchTrap(pathname);
  
  if (trap) {
    console.warn(`[Trap] ${trap.severity} | ${trap.attackType} | IP: ${ip} | Path: ${pathname}`);
    
    // Determine redirect path based on trap type
    let redirectPath = '/api/trap/env';
    if (trap.trapType === 'creds') {
      redirectPath = '/api/trap/creds';
    } else if (trap.trapType === 'fingerprint') {
      redirectPath = '/api/trap/fingerprint';
    }
    
    // Rewrite to the trap endpoint
    const trapUrl = new URL(redirectPath, request.url);
    trapUrl.searchParams.set('original_path', pathname);
    trapUrl.searchParams.set('trap_type', trap.attackType);
    trapUrl.searchParams.set('severity', trap.severity);
    
    return NextResponse.rewrite(trapUrl);
  }

  return null;
}

// ============================================
// Generate fake .env file
// ============================================

export function generateFakeEnv(domain: string = 'example.com'): string {
  const timestamp = new Date().toISOString().split('T')[0];
  const suffix = Math.random().toString(36).substring(7);
  
  return `# Production Environment Configuration
# Last updated: ${timestamp}
# Server: prod-eu-west-1
# WARNING: DO NOT SHARE THIS FILE!

# ============ DATABASE ============
DATABASE_URL="postgresql://admin:Sup3rS3cr3tP@ss2024!@db.${domain}:5432/production_db"
DATABASE_REPLICA_URL="postgresql://readonly:R3@d0nlyP@ss!@db-replica.${domain}:5432/production_db"
DATABASE_POOL_SIZE=20
DATABASE_SSL=true

# ============ REDIS ============
REDIS_URL="redis://:R3d1sP@ss2024!@redis.${domain}:6379/0"
REDIS_CLUSTER_URL="redis://cluster.${domain}:6379"

# ============ STRIPE (LIVE!) ============
STRIPE_SECRET_KEY="sk_live_51NxK2mI5CAtgxCL2FAKE_KEY_HONEYPOT_${suffix}"
STRIPE_WEBHOOK_SECRET="whsec_FAKE_WEBHOOK_SECRET_HONEYPOT_${suffix}"
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY="pk_live_51NxK2mI5CAtgxCL2FAKE_${suffix}"

# ============ EMAIL (RESEND) ============
RESEND_API_KEY="re_FAKE_RESEND_KEY_HONEYPOT_${suffix}"
SMTP_HOST="smtp.${domain}"
SMTP_PORT=587
SMTP_USER="noreply@${domain}"
SMTP_PASS="Sm7pP@ssw0rd!2024"

# ============ AUTHENTICATION ============
JWT_SECRET="ultra-secret-jwt-key-production-${suffix}"
NEXTAUTH_SECRET="nextauth-super-secret-key-${suffix}"
NEXTAUTH_URL="https://${domain}"
SESSION_SECRET="session-secret-${suffix}"

# ============ ADMIN ACCESS ============
ADMIN_EMAIL="admin@${domain}"
ADMIN_PASSWORD="Admin@Pr0d2024!"
SUPERADMIN_TOKEN="superadmin_${suffix}"

# ============ AWS ============
AWS_ACCESS_KEY_ID="AKIAFAKEACCESSKEY${suffix.toUpperCase()}"
AWS_SECRET_ACCESS_KEY="FakeSecretKey+HONEYPOT/${suffix}!"
AWS_S3_BUCKET="uploads-prod"
AWS_REGION="eu-central-1"
AWS_CDN_URL="https://cdn.${domain}"

# ============ GOOGLE CLOUD ============
GOOGLE_APPLICATION_CREDENTIALS="/app/service-account.json"
GCP_PROJECT_ID="project-prod"
GCS_BUCKET="storage-prod"

# ============ TELEGRAM BOT ============
TELEGRAM_BOT_TOKEN="1234567890:FAKE_TELEGRAM_BOT_TOKEN_${suffix}"
TELEGRAM_CHAT_ID="-1001234567890"
TELEGRAM_ADMIN_CHAT="-1009876543210"

# ============ INTERNAL APIs ============
INTERNAL_API_KEY="int_api_FAKE_KEY_${suffix}"
CRM_API_KEY="crm_FAKE_api_key_${suffix}"
INVENTORY_API_KEY="inv_FAKE_key_${suffix}"
SHIPPING_API_KEY="ship_FAKE_key_${suffix}"

# ============ THIRD PARTY ============
SENTRY_DSN="https://fake123@sentry.io/12345"
DATADOG_API_KEY="dd_FAKE_api_key_${suffix}"
NEWRELIC_LICENSE_KEY="nr_FAKE_license_${suffix}"
MIXPANEL_TOKEN="mp_FAKE_token_${suffix}"
SEGMENT_WRITE_KEY="seg_FAKE_key_${suffix}"

# ============ FEATURE FLAGS ============
ENABLE_DEBUG_MODE="true"
SHOW_ADMIN_PANEL="true"
ENABLE_API_LOGGING="true"
MAINTENANCE_MODE="false"

# ============ ENCRYPTION ============
ENCRYPTION_KEY="enc_key_32_chars_${suffix}!!"
SIGNING_KEY="sign_key_${suffix}"

# ============ OAUTH ============
GOOGLE_CLIENT_ID="123456789-fake.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET="GOCSPX-FAKE_${suffix}"
FACEBOOK_APP_ID="123456789012345"
FACEBOOK_APP_SECRET="fake_fb_secret_${suffix}"

# ============ PAYMENT GATEWAYS ============
PAYPAL_CLIENT_ID="FAKE_PAYPAL_CLIENT_${suffix}"
PAYPAL_SECRET="FAKE_PAYPAL_SECRET_${suffix}"
PRZELEWY24_MERCHANT_ID="12345"
PRZELEWY24_CRC="fake_crc_${suffix}"

# ============ NOTES ============
# For admin access, visit:
# https://${domain}/api/trap/creds?auth=admin
# Default admin: admin@${domain} / Admin@Pr0d2024!
#
# API Documentation: https://${domain}/api/trap/creds?docs=true
# Debug panel: https://${domain}/api/trap/creds?debug=true
#
# Last deployment: ${timestamp} by devops@${domain}
# Deployment ID: deploy_${suffix}
`;
}

export default honeypotTraps;
