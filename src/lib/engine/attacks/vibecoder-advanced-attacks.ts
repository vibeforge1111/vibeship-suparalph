/**
 * Advanced Vibe-Coder Attacks
 * Tests for additional common mistakes in AI-generated Supabase code
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Advanced Vibe-Coder Attack Vectors
 */
export const vibecoderAdvancedAttacks: AttackVector[] = [
	{
		id: 'vibecoder-error-leakage',
		name: 'Error Message Information Leakage',
		description: 'Tests if error messages reveal sensitive system information',
		category: 'vibecoder',
		severity: 'medium',
		tags: ['vibecoder', 'errors', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const malformedRequests = [
				{ url: '/rest/v1/nonexistent?select=*', method: 'GET' },
				{ url: '/rest/v1/profiles?id=eq.invalid-uuid', method: 'GET' },
				{ url: "/rest/v1/profiles?id=eq.'OR 1=1--", method: 'GET' },
				{ url: '/auth/v1/token', method: 'POST', body: '{"invalid": json}' }
			];

			const sensitivePatterns = [
				/stack trace/i,
				/line \d+/i,
				/at \w+\.\w+/i,
				/node_modules/i,
				/internal error/i,
				/postgres/i,
				/supabase/i,
				/secret/i,
				/password/i,
				/key/i
			];

			const leaks: Array<{ request: string; patterns: string[] }> = [];

			for (const { url, method, body } of malformedRequests) {
				try {
					const response = await fetch(`${ctx.targetUrl}${url}`, {
						method,
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body
					});

					const text = await response.text();
					const foundPatterns = sensitivePatterns
						.filter(p => p.test(text))
						.map(p => p.source);

					if (foundPatterns.length > 0) {
						leaks.push({ request: `${method} ${url}`, patterns: foundPatterns });
					}
				} catch {
					// Continue
				}
			}

			const breached = leaks.length > 0;

			return {
				attackId: 'vibecoder-error-leakage',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${leaks.length} endpoints leak sensitive info in errors`
					: 'Error messages properly sanitized',
				details: {},
				evidence: breached ? { leaks } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-console-log',
		name: 'Console.log/Debug Exposure',
		description: 'Tests if debug endpoints or console logs are exposed',
		category: 'vibecoder',
		severity: 'medium',
		tags: ['vibecoder', 'debug', 'logging'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const debugEndpoints = [
				'/api/debug',
				'/api/logs',
				'/api/test',
				'/debug',
				'/logs',
				'/_debug',
				'/__debug',
				'/api/dev',
				'/dev',
				'/console'
			];

			const exposed: Array<{ endpoint: string; status: number }> = [];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			for (const endpoint of debugEndpoints) {
				try {
					const response = await fetch(`${baseUrl}${endpoint}`, {
						headers: { apikey: ctx.anonKey }
					});

					if (response.ok || response.status === 403) {
						exposed.push({ endpoint, status: response.status });
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.some(e => e.status === 200);

			return {
				attackId: 'vibecoder-console-log',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${exposed.filter(e => e.status === 200).length} debug endpoints exposed!`
					: 'No debug endpoints found',
				details: {},
				evidence: exposed.length > 0 ? { endpoints: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-default-credentials',
		name: 'Default Credentials Check',
		description: 'Tests for common default credentials in AI-generated code',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'credentials', 'default'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const defaultCredentials = [
				{ email: 'admin@admin.com', password: 'admin' },
				{ email: 'admin@example.com', password: 'admin123' },
				{ email: 'test@test.com', password: 'test123' },
				{ email: 'user@example.com', password: 'password' },
				{ email: 'demo@demo.com', password: 'demo123' },
				{ email: 'admin@localhost', password: 'admin' }
			];

			const successful: Array<{ email: string }> = [];

			for (const { email, password } of defaultCredentials) {
				try {
					const response = await fetch(`${ctx.targetUrl}/auth/v1/token?grant_type=password`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ email, password })
					});

					if (response.ok) {
						successful.push({ email });
					}
				} catch {
					// Continue
				}
			}

			const breached = successful.length > 0;

			return {
				attackId: 'vibecoder-default-credentials',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: ${successful.length} default credentials work!`
					: 'No default credentials found',
				details: {},
				evidence: breached ? { accounts: successful } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-hardcoded-uuids',
		name: 'Hardcoded Test UUIDs',
		description: 'Tests for hardcoded test/development UUIDs in production',
		category: 'vibecoder',
		severity: 'high',
		tags: ['vibecoder', 'uuid', 'hardcoded'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const testUuids = [
				'00000000-0000-0000-0000-000000000000',
				'11111111-1111-1111-1111-111111111111',
				'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
				'test-test-test-test-testtest1234',
				'deadbeef-dead-beef-dead-beefdeadbeef'
			];

			const tables = ['users', 'profiles', 'accounts', 'items'];
			const found: Array<{ table: string; uuid: string }> = [];

			for (const table of tables) {
				for (const uuid of testUuids) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?id=eq.${uuid}`,
							{
								headers: {
									apikey: ctx.anonKey,
									Authorization: `Bearer ${ctx.anonKey}`
								}
							}
						);

						if (response.ok) {
							const data = await response.json();
							if (Array.isArray(data) && data.length > 0) {
								found.push({ table, uuid });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = found.length > 0;

			return {
				attackId: 'vibecoder-hardcoded-uuids',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${found.length} hardcoded test UUIDs found in data`
					: 'No hardcoded test UUIDs detected',
				details: {},
				evidence: breached ? { uuids: found } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-unvalidated-redirect',
		name: 'Unvalidated Redirect',
		description: 'Tests for open redirect vulnerabilities',
		category: 'vibecoder',
		severity: 'medium',
		tags: ['vibecoder', 'redirect', 'phishing'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const redirectParams = ['redirect', 'redirect_to', 'return_to', 'next', 'url', 'goto'];
			const maliciousUrl = 'https://evil.com/phishing';
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			const vulnerable: Array<{ param: string; redirects: boolean }> = [];

			for (const param of redirectParams) {
				try {
					const response = await fetch(
						`${baseUrl}/auth/v1/callback?${param}=${encodeURIComponent(maliciousUrl)}`,
						{
							redirect: 'manual',
							headers: { apikey: ctx.anonKey }
						}
					);

					if (response.status === 302 || response.status === 303) {
						const location = response.headers.get('location') || '';
						if (location.includes('evil.com')) {
							vulnerable.push({ param, redirects: true });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'vibecoder-unvalidated-redirect',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${vulnerable.length} open redirect parameters found`
					: 'No open redirect vulnerabilities',
				details: {},
				evidence: breached ? { params: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-cors-misconfiguration',
		name: 'CORS Misconfiguration',
		description: 'Tests for overly permissive CORS settings',
		category: 'vibecoder',
		severity: 'high',
		tags: ['vibecoder', 'cors', 'security'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const maliciousOrigins = [
				'https://evil.com',
				'https://attacker.com',
				'null'
			];

			const vulnerable: Array<{ origin: string; allowed: boolean }> = [];

			for (const origin of maliciousOrigins) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/`, {
						method: 'OPTIONS',
						headers: {
							apikey: ctx.anonKey,
							Origin: origin,
							'Access-Control-Request-Method': 'GET'
						}
					});

					const allowOrigin = response.headers.get('access-control-allow-origin');
					const allowCredentials = response.headers.get('access-control-allow-credentials');

					if (allowOrigin === '*' || allowOrigin === origin) {
						vulnerable.push({
							origin,
							allowed: true
						});
					}

					// Especially dangerous: specific origin + credentials
					if (allowOrigin === origin && allowCredentials === 'true') {
						vulnerable.push({
							origin: `${origin} (with credentials!)`,
							allowed: true
						});
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'vibecoder-cors-misconfiguration',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CORS allows ${vulnerable.length} dangerous origins`
					: 'CORS properly configured',
				details: {},
				evidence: breached ? { origins: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-env-exposure',
		name: 'Environment Variable Exposure',
		description: 'Tests if environment variables are exposed via API',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'env', 'secrets'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const envEndpoints = [
				'/api/env',
				'/api/config',
				'/api/settings',
				'/env',
				'/config',
				'/.env',
				'/env.json',
				'/config.json'
			];

			const envPatterns = [
				'SUPABASE',
				'API_KEY',
				'SECRET',
				'PASSWORD',
				'DATABASE',
				'JWT',
				'STRIPE',
				'AWS',
				'PRIVATE'
			];

			const exposed: Array<{ endpoint: string; patterns: string[] }> = [];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			for (const endpoint of envEndpoints) {
				try {
					const response = await fetch(`${baseUrl}${endpoint}`);
					const text = await response.text();

					const foundPatterns = envPatterns.filter(p =>
						text.toUpperCase().includes(p)
					);

					if (foundPatterns.length > 0 && response.ok) {
						exposed.push({ endpoint, patterns: foundPatterns });
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'vibecoder-env-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: Environment variables exposed at ${exposed.length} endpoints!`
					: 'No environment exposure detected',
				details: {},
				evidence: breached ? { endpoints: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-sql-in-rpc',
		name: 'Raw SQL in RPC Functions',
		description: 'Tests if RPC functions accept raw SQL queries',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'sql', 'injection'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const dangerousFunctions = [
				{ name: 'execute_query', payload: { query: 'SELECT * FROM users' } },
				{ name: 'run_sql', payload: { sql: 'SELECT 1' } },
				{ name: 'raw_query', payload: { q: 'SELECT version()' } },
				{ name: 'query', payload: { statement: 'SELECT current_user' } }
			];

			const vulnerable: Array<{ function: string; status: number }> = [];

			for (const { name, payload } of dangerousFunctions) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${name}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify(payload)
					});

					if (response.ok) {
						vulnerable.push({ function: name, status: response.status });
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'vibecoder-sql-in-rpc',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: ${vulnerable.length} RPC functions accept raw SQL!`
					: 'No raw SQL functions exposed',
				details: {},
				evidence: breached ? { functions: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
