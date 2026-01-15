/**
 * Infrastructure & Configuration Attacks
 * Tests for infrastructure-level security misconfigurations
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Infrastructure Attack Vectors
 */
export const infrastructureAttacks: AttackVector[] = [
	{
		id: 'infra-service-key-exposure',
		name: 'Service Key Exposure Check',
		description: 'Tests if service role key might be exposed client-side',
		category: 'api',
		severity: 'critical',
		tags: ['infrastructure', 'service-key', 'exposure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Check if the anon key has service role privileges
			const serviceRoleChecks: Array<{ endpoint: string; method: string; hasAccess: boolean }> = [];

			// Service role should be able to bypass RLS
			const tests = [
				{ url: '/rest/v1/auth.users?select=*&limit=1', method: 'GET' },
				{ url: '/rest/v1/storage.buckets?select=*', method: 'GET' },
				{ url: '/auth/v1/admin/users', method: 'GET' }
			];

			for (const { url, method } of tests) {
				try {
					const response = await fetch(`${ctx.targetUrl}${url}`, {
						method,
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`
						}
					});

					if (response.ok) {
						serviceRoleChecks.push({ endpoint: url, method, hasAccess: true });
					}
				} catch {
					// Continue
				}
			}

			const breached = serviceRoleChecks.some(c => c.hasAccess);

			return {
				attackId: 'infra-service-key-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'CRITICAL: Anon key has service role access - key may be exposed!'
					: 'Service role key properly protected',
				details: {},
				evidence: breached ? { checks: serviceRoleChecks } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-security-headers',
		name: 'Security Headers Missing',
		description: 'Checks for important security headers',
		category: 'api',
		severity: 'medium',
		tags: ['infrastructure', 'headers', 'security'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const requiredHeaders = [
				'x-frame-options',
				'x-content-type-options',
				'strict-transport-security',
				'x-xss-protection',
				'content-security-policy'
			];

			const missing: string[] = [];
			const present: string[] = [];

			try {
				const response = await fetch(`${ctx.targetUrl}/rest/v1/`, {
					headers: { apikey: ctx.anonKey }
				});

				for (const header of requiredHeaders) {
					if (response.headers.get(header)) {
						present.push(header);
					} else {
						missing.push(header);
					}
				}
			} catch {
				return {
					attackId: 'infra-security-headers',
					status: 'error',
					breached: false,
					summary: 'Could not check security headers',
					details: {},
					timestamp: new Date().toISOString(),
					duration: 0
				};
			}

			const breached = missing.length > 2;

			return {
				attackId: 'infra-security-headers',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${missing.length} security headers missing`
					: 'Security headers properly configured',
				details: {},
				evidence: { missing, present },
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-api-versioning',
		name: 'API Version Exposure',
		description: 'Checks if API exposes version information',
		category: 'api',
		severity: 'low',
		tags: ['infrastructure', 'versioning', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const versionInfo: Record<string, string> = {};

			try {
				const response = await fetch(`${ctx.targetUrl}/rest/v1/`, {
					headers: { apikey: ctx.anonKey }
				});

				// Check server header
				const server = response.headers.get('server');
				if (server) versionInfo.server = server;

				// Check x-powered-by
				const poweredBy = response.headers.get('x-powered-by');
				if (poweredBy) versionInfo.poweredBy = poweredBy;

				// Check postgrest version
				const postgrest = response.headers.get('content-profile');
				if (postgrest) versionInfo.postgrest = postgrest;

				// Try to get version from root
				const text = await response.text();
				const versionMatch = text.match(/version["\s:]+([0-9.]+)/i);
				if (versionMatch) versionInfo.apiVersion = versionMatch[1];
			} catch {
				// Continue
			}

			const breached = Object.keys(versionInfo).length > 1;

			return {
				attackId: 'infra-api-versioning',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'API version information exposed'
					: 'Version information not exposed',
				details: {},
				evidence: Object.keys(versionInfo).length > 0 ? { versions: versionInfo } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-admin-endpoints',
		name: 'Admin Endpoint Exposure',
		description: 'Checks if admin endpoints are accessible',
		category: 'api',
		severity: 'critical',
		tags: ['infrastructure', 'admin', 'exposure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const adminEndpoints = [
				'/auth/v1/admin/users',
				'/auth/v1/admin/audit',
				'/auth/v1/admin/config',
				'/rest/v1/rpc/admin_',
				'/admin',
				'/api/admin',
				'/_admin',
				'/dashboard',
				'/manage'
			];

			const accessible: Array<{ endpoint: string; status: number }> = [];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			for (const endpoint of adminEndpoints) {
				try {
					const response = await fetch(`${baseUrl}${endpoint}`, {
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`
						}
					});

					if (response.ok || response.status === 403) {
						accessible.push({ endpoint, status: response.status });
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.some(e => e.status === 200);

			return {
				attackId: 'infra-admin-endpoints',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.filter(e => e.status === 200).length} admin endpoints exposed!`
					: 'Admin endpoints properly protected',
				details: {},
				evidence: accessible.length > 0 ? { endpoints: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-graphql-introspection',
		name: 'GraphQL Introspection Enabled',
		description: 'Checks if GraphQL introspection is enabled (if GraphQL is active)',
		category: 'api',
		severity: 'medium',
		tags: ['infrastructure', 'graphql', 'introspection'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const graphqlEndpoints = ['/graphql/v1', '/graphql', '/v1/graphql'];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			let introspectionEnabled = false;
			let schemaTypes = 0;

			for (const endpoint of graphqlEndpoints) {
				try {
					const response = await fetch(`${baseUrl}${endpoint}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							query: `
								query IntrospectionQuery {
									__schema {
										types { name }
									}
								}
							`
						})
					});

					if (response.ok) {
						const data = await response.json();
						if (data?.data?.__schema?.types) {
							introspectionEnabled = true;
							schemaTypes = data.data.__schema.types.length;
							break;
						}
					}
				} catch {
					// Continue
				}
			}

			return {
				attackId: 'infra-graphql-introspection',
				status: introspectionEnabled ? 'breached' : 'secure',
				breached: introspectionEnabled,
				summary: introspectionEnabled
					? `GraphQL introspection enabled - ${schemaTypes} types exposed`
					: 'GraphQL introspection disabled or GraphQL not enabled',
				details: {},
				evidence: introspectionEnabled ? { typesExposed: schemaTypes } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-webhook-exposure',
		name: 'Webhook Configuration Exposure',
		description: 'Tests if webhook configurations are accessible',
		category: 'database',
		severity: 'high',
		tags: ['infrastructure', 'webhooks', 'configuration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const webhookTables = [
				'supabase_functions.hooks',
				'webhooks',
				'hooks',
				'triggers',
				'event_triggers'
			];

			const exposed: Array<{ table: string; count: number }> = [];

			for (const table of webhookTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=5`,
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
							exposed.push({ table, count: data.length });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'infra-webhook-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Webhook configurations exposed in ${exposed.length} tables`
					: 'Webhook configurations properly protected',
				details: {},
				evidence: breached ? { tables: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-ssl-configuration',
		name: 'SSL/TLS Configuration',
		description: 'Checks SSL/TLS security configuration',
		category: 'api',
		severity: 'high',
		tags: ['infrastructure', 'ssl', 'tls'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const issues: string[] = [];

			// Check if HTTPS is enforced
			const httpUrl = ctx.targetUrl.replace('https://', 'http://');
			if (!httpUrl.includes('localhost') && !httpUrl.includes('127.0.0.1')) {
				try {
					const response = await fetch(httpUrl, {
						redirect: 'manual'
					});

					if (response.ok) {
						issues.push('HTTP connections accepted without redirect to HTTPS');
					} else if (response.status !== 301 && response.status !== 302) {
						issues.push('HTTP not properly redirecting to HTTPS');
					}
				} catch {
					// Connection refused is good - HTTP not accepted
				}
			}

			// Check HSTS header
			try {
				const response = await fetch(`${ctx.targetUrl}/rest/v1/`, {
					headers: { apikey: ctx.anonKey }
				});

				const hsts = response.headers.get('strict-transport-security');
				if (!hsts) {
					issues.push('HSTS header missing');
				} else if (!hsts.includes('max-age=31536000')) {
					issues.push('HSTS max-age should be at least 1 year');
				}
				if (hsts && !hsts.includes('includeSubDomains')) {
					issues.push('HSTS should include subdomains');
				}
			} catch {
				// Continue
			}

			const breached = issues.length > 1;

			return {
				attackId: 'infra-ssl-configuration',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${issues.length} SSL/TLS configuration issues found`
					: 'SSL/TLS properly configured',
				details: {},
				evidence: issues.length > 0 ? { issues } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'infra-rate-limiting',
		name: 'API Rate Limiting',
		description: 'Tests if API endpoints are rate limited',
		category: 'api',
		severity: 'high',
		tags: ['infrastructure', 'rate-limit', 'dos'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const requestCount = 50;
			let successCount = 0;
			let rateLimited = false;

			for (let i = 0; i < requestCount; i++) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/`, {
						headers: { apikey: ctx.anonKey }
					});

					if (response.status === 429) {
						rateLimited = true;
						break;
					}
					if (response.ok) {
						successCount++;
					}
				} catch {
					break;
				}
			}

			const breached = !rateLimited && successCount >= requestCount;

			return {
				attackId: 'infra-rate-limiting',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `No rate limiting - ${successCount} requests succeeded`
					: rateLimited
						? `Rate limiting active after ${successCount} requests`
						: 'Rate limiting appears configured',
				details: {},
				evidence: { requestsMade: successCount, wasRateLimited: rateLimited },
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
