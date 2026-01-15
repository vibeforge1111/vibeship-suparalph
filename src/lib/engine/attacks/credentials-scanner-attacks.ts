/**
 * Leaked Credentials Scanner
 * Scans for exposed API keys, secrets, and credentials
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Common file paths that might contain leaked credentials
 */
const SENSITIVE_PATHS = [
	'/.env',
	'/.env.local',
	'/.env.production',
	'/.env.development',
	'/env.js',
	'/config.js',
	'/config.json',
	'/settings.json',
	'/.git/config',
	'/.git/HEAD',
	'/wp-config.php',
	'/configuration.php',
	'/web.config',
	'/appsettings.json',
	'/secrets.json',
	'/credentials.json',
	'/.aws/credentials',
	'/.docker/config.json',
	'/supabase/.env',
	'/supabase/config.toml',
	'/.supabase/config.toml'
];

/**
 * Patterns that indicate leaked credentials
 */
const CREDENTIAL_PATTERNS = [
	{ name: 'Supabase Anon Key', pattern: /SUPABASE_ANON_KEY\s*[=:]\s*["']?eyJ[A-Za-z0-9_-]+/i },
	{ name: 'Supabase Service Role', pattern: /SUPABASE_SERVICE_ROLE[_KEY]*\s*[=:]\s*["']?eyJ[A-Za-z0-9_-]+/i },
	{ name: 'Supabase URL', pattern: /SUPABASE_URL\s*[=:]\s*["']?https:\/\/[a-z0-9]+\.supabase\.co/i },
	{ name: 'Database URL', pattern: /DATABASE_URL\s*[=:]\s*["']?postgres(ql)?:\/\/[^\s"']+/i },
	{ name: 'JWT Secret', pattern: /JWT_SECRET\s*[=:]\s*["']?[A-Za-z0-9+/=]{20,}/i },
	{ name: 'API Key Generic', pattern: /API_KEY\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}/i },
	{ name: 'Secret Key', pattern: /SECRET_KEY\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}/i },
	{ name: 'Private Key', pattern: /PRIVATE_KEY\s*[=:]\s*["']?[A-Za-z0-9+/=\-_]{20,}/i },
	{ name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/i },
	{ name: 'AWS Secret Key', pattern: /AWS_SECRET[_ACCESS_KEY]*\s*[=:]\s*["']?[A-Za-z0-9+/]{40}/i },
	{ name: 'Stripe Key', pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/i },
	{ name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/i },
	{ name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{48}/i },
	{ name: 'Postgres Password', pattern: /POSTGRES_PASSWORD\s*[=:]\s*["']?[^\s"']+/i },
	{ name: 'Connection String', pattern: /postgresql:\/\/[^:]+:[^@]+@[^\s"']+/i }
];

export const credentialsScannerAttacks: AttackVector[] = [
	{
		id: 'credentials-exposed-files',
		name: 'Exposed Configuration Files',
		description: 'Scans for publicly accessible configuration files containing credentials',
		category: 'api',
		severity: 'critical',
		tags: ['credentials', 'config', 'exposure', 'secrets'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const exposedFiles: Array<{ path: string; credentials: string[] }> = [];
			let breached = false;

			// Extract base URL
			const baseUrl = ctx.targetUrl.replace(/\/rest\/v1\/?$/, '');

			for (const path of SENSITIVE_PATHS) {
				try {
					const res = await fetch(`${baseUrl}${path}`, {
						headers: { 'Accept': '*/*' },
						signal: ctx.signal
					});

					if (res.ok) {
						const text = await res.text();
						const foundCredentials: string[] = [];

						for (const { name, pattern } of CREDENTIAL_PATTERNS) {
							if (pattern.test(text)) {
								foundCredentials.push(name);
							}
						}

						if (foundCredentials.length > 0) {
							exposedFiles.push({ path, credentials: foundCredentials });
							breached = true;
						} else if (text.length > 0 && (path.includes('.env') || path.includes('config'))) {
							// File exists but no patterns matched - still suspicious
							exposedFiles.push({ path, credentials: ['File accessible (no patterns matched)'] });
						}
					}
				} catch {}
			}

			return {
				attackId: 'credentials-exposed-files',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: ${exposedFiles.length} config files with credentials exposed!`
					: 'No exposed configuration files found',
				details: { exposedFiles, scannedPaths: SENSITIVE_PATHS.length },
				evidence: breached ? { exposedFiles } : undefined
			};
		}
	},

	{
		id: 'credentials-in-html-source',
		name: 'Credentials in HTML Source',
		description: 'Checks if credentials are embedded in HTML page source',
		category: 'api',
		severity: 'high',
		tags: ['credentials', 'html', 'exposure', 'client-side'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: Array<{ url: string; credential: string }> = [];
			let breached = false;

			const baseUrl = ctx.targetUrl.replace(/\/rest\/v1\/?$/, '');
			const pagesToCheck = ['/', '/index.html', '/app', '/dashboard', '/login', '/admin'];

			for (const page of pagesToCheck) {
				try {
					const res = await fetch(`${baseUrl}${page}`, {
						headers: { 'Accept': 'text/html' },
						signal: ctx.signal
					});

					if (res.ok) {
						const html = await res.text();

						// Check for inline scripts with credentials
						for (const { name, pattern } of CREDENTIAL_PATTERNS) {
							if (pattern.test(html)) {
								findings.push({ url: page, credential: name });
								breached = true;
							}
						}

						// Check for window.__ENV__ or similar patterns
						if (/window\.__ENV__|window\.ENV|window\.config/i.test(html)) {
							const envMatch = html.match(/window\.__ENV__\s*=\s*({[^}]+})/);
							if (envMatch) {
								findings.push({ url: page, credential: 'window.__ENV__ object exposed' });
							}
						}
					}
				} catch {}
			}

			return {
				attackId: 'credentials-in-html-source',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Found ${findings.length} credentials embedded in HTML!`
					: 'No credentials found in HTML source',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'credentials-in-js-bundle',
		name: 'Credentials in JavaScript Bundles',
		description: 'Scans JavaScript bundles for hardcoded credentials',
		category: 'api',
		severity: 'critical',
		tags: ['credentials', 'javascript', 'bundle', 'exposure'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: Array<{ file: string; credentials: string[] }> = [];
			let breached = false;

			const baseUrl = ctx.targetUrl.replace(/\/rest\/v1\/?$/, '');

			// Common JS bundle paths
			const jsPaths = [
				'/main.js',
				'/app.js',
				'/bundle.js',
				'/index.js',
				'/static/js/main.js',
				'/static/js/bundle.js',
				'/_next/static/chunks/main.js',
				'/_next/static/chunks/app.js',
				'/assets/index.js',
				'/build/bundle.js',
				'/dist/bundle.js'
			];

			for (const jsPath of jsPaths) {
				try {
					const res = await fetch(`${baseUrl}${jsPath}`, {
						headers: { 'Accept': 'application/javascript' },
						signal: ctx.signal
					});

					if (res.ok) {
						const js = await res.text();
						const foundCredentials: string[] = [];

						for (const { name, pattern } of CREDENTIAL_PATTERNS) {
							if (pattern.test(js)) {
								foundCredentials.push(name);
							}
						}

						// Also check for hardcoded Supabase URLs with keys
						if (/createClient\s*\(\s*["'][^"']+supabase\.co["']\s*,\s*["']eyJ/.test(js)) {
							foundCredentials.push('Hardcoded Supabase client initialization');
						}

						if (foundCredentials.length > 0) {
							findings.push({ file: jsPath, credentials: foundCredentials });
							breached = true;
						}
					}
				} catch {}
			}

			return {
				attackId: 'credentials-in-js-bundle',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: ${findings.length} JS files contain credentials!`
					: 'No credentials found in JavaScript bundles',
				details: { findings, scannedFiles: jsPaths.length },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'credentials-git-exposure',
		name: 'Git Repository Exposure',
		description: 'Checks if .git directory is publicly accessible',
		category: 'api',
		severity: 'critical',
		tags: ['git', 'exposure', 'source-code', 'credentials'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const baseUrl = ctx.targetUrl.replace(/\/rest\/v1\/?$/, '');

			// Check for .git exposure
			const gitPaths = [
				'/.git/HEAD',
				'/.git/config',
				'/.git/index',
				'/.git/logs/HEAD',
				'/.git/refs/heads/main',
				'/.git/refs/heads/master'
			];

			for (const gitPath of gitPaths) {
				try {
					const res = await fetch(`${baseUrl}${gitPath}`, {
						signal: ctx.signal
					});

					if (res.ok) {
						const text = await res.text();
						if (text.includes('ref:') || text.includes('[core]') || text.includes('commit')) {
							findings.push(`Git file exposed: ${gitPath}`);
							breached = true;
						}
					}
				} catch {}
			}

			// Check for common git-related credential leaks
			try {
				const configRes = await fetch(`${baseUrl}/.git/config`, { signal: ctx.signal });
				if (configRes.ok) {
					const config = await configRes.text();
					if (/password|token|oauth/i.test(config)) {
						findings.push('Git config contains potential credentials!');
					}
				}
			} catch {}

			return {
				attackId: 'credentials-git-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: Git repository exposed! ${findings.length} files accessible`
					: 'Git repository not exposed',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'credentials-api-response-leak',
		name: 'Credentials in API Responses',
		description: 'Checks if API responses leak sensitive credentials',
		category: 'api',
		severity: 'high',
		tags: ['api', 'response', 'credentials', 'leak'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: Array<{ endpoint: string; leaked: string[] }> = [];
			let breached = false;

			// Endpoints that might leak credentials
			const endpoints = [
				'/rest/v1/settings?select=*',
				'/rest/v1/config?select=*',
				'/rest/v1/api_keys?select=*',
				'/rest/v1/secrets?select=*',
				'/rest/v1/credentials?select=*',
				'/rest/v1/tokens?select=*',
				'/rest/v1/users?select=*',
				'/rest/v1/accounts?select=*'
			];

			// Sensitive field names
			const sensitiveFields = [
				'password', 'secret', 'token', 'api_key', 'apikey', 'private_key',
				'access_token', 'refresh_token', 'auth_token', 'service_key',
				'encryption_key', 'signing_key', 'client_secret'
			];

			for (const endpoint of endpoints) {
				try {
					const res = await fetch(`${ctx.targetUrl.replace('/rest/v1', '')}${endpoint}`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (res.ok) {
						const data = await res.json();
						const leaked: string[] = [];

						// Check if response contains sensitive fields
						const checkObject = (obj: unknown, path = ''): void => {
							if (!obj || typeof obj !== 'object') return;

							for (const [key, value] of Object.entries(obj)) {
								const lowerKey = key.toLowerCase();
								if (sensitiveFields.some(f => lowerKey.includes(f))) {
									if (value && typeof value === 'string' && value.length > 0) {
										leaked.push(`${path}${key}`);
									}
								}
								if (typeof value === 'object') {
									checkObject(value, `${path}${key}.`);
								}
							}
						};

						if (Array.isArray(data)) {
							data.forEach((item, i) => checkObject(item, `[${i}].`));
						} else {
							checkObject(data);
						}

						if (leaked.length > 0) {
							findings.push({ endpoint, leaked });
							breached = true;
						}
					}
				} catch {}
			}

			return {
				attackId: 'credentials-api-response-leak',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Found ${findings.length} API endpoints leaking credentials!`
					: 'No credential leaks in API responses',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'credentials-error-disclosure',
		name: 'Credentials in Error Messages',
		description: 'Tests if error messages disclose credentials or connection strings',
		category: 'api',
		severity: 'medium',
		tags: ['error', 'disclosure', 'credentials', 'debug'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Trigger errors that might leak info
			const errorTriggers = [
				{ url: '/rest/v1/nonexistent_table_12345', method: 'GET' },
				{ url: '/rest/v1/rpc/nonexistent_function', method: 'POST', body: '{}' },
				{ url: '/rest/v1/users?select=*&invalid_param', method: 'GET' },
				{ url: '/rest/v1/', method: 'DELETE' },
				{ url: "/rest/v1/users?id=eq.'; DROP TABLE users;--", method: 'GET' }
			];

			for (const trigger of errorTriggers) {
				try {
					const res = await fetch(`${ctx.targetUrl.replace('/rest/v1', '')}${trigger.url}`, {
						method: trigger.method,
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: trigger.body,
						signal: ctx.signal
					});

					const text = await res.text();

					// Check for credential patterns in error response
					if (/password|postgres:\/\/|connection string|api[_-]?key|secret/i.test(text)) {
						findings.push(`Error at ${trigger.url} may leak credentials`);
						breached = true;
					}

					// Check for stack traces
					if (/at\s+\S+\s+\([^)]+:\d+:\d+\)|Traceback|Stack trace/i.test(text)) {
						findings.push(`Stack trace exposed at ${trigger.url}`);
					}

					// Check for internal paths
					if (/\/home\/|\/var\/|C:\\|\/usr\/|node_modules/i.test(text)) {
						findings.push(`Internal paths exposed at ${trigger.url}`);
					}
				} catch {}
			}

			return {
				attackId: 'credentials-error-disclosure',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: breached
					? `Error messages may leak credentials! ${findings.length} issues found`
					: findings.length > 0
						? `${findings.length} information disclosure issues found`
						: 'Error messages appear safe',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	}
];
