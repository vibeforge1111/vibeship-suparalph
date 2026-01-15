/**
 * API/PostgREST Attacks
 * Tests for Supabase REST API and PostgREST vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * API Attack Vectors
 */
export const apiAttacks: AttackVector[] = [
	{
		id: 'api-schema-exposure',
		name: 'Schema Exposure via OpenAPI',
		description: 'Checks if database schema is exposed through OpenAPI endpoint',
		category: 'api',
		severity: 'medium',
		tags: ['api', 'schema', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const endpoints = [
				'/rest/v1/',
				'/rest/v1/?apikey=',
				'/'
			];

			let schemaExposed = false;
			let schemaData: unknown = null;

			for (const endpoint of endpoints) {
				try {
					const response = await fetch(`${ctx.targetUrl}${endpoint}`, {
						headers: {
							apikey: ctx.anonKey,
							Accept: 'application/openapi+json'
						}
					});

					if (response.ok) {
						const data = await response.json();
						if (data.paths || data.definitions || data.components) {
							schemaExposed = true;
							schemaData = {
								pathCount: Object.keys(data.paths || {}).length,
								hasDefinitions: !!data.definitions || !!data.components
							};
							break;
						}
					}
				} catch {
					// Continue
				}
			}

			return {
				attackId: 'api-schema-exposure',
				status: schemaExposed ? 'breached' : 'secure',
				breached: schemaExposed,
				summary: schemaExposed
					? 'Database schema exposed via OpenAPI endpoint'
					: 'Schema not publicly exposed',
				details: {},
				evidence: schemaExposed ? { schema: schemaData } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-bulk-insert',
		name: 'Unrestricted Bulk Insert',
		description: 'Tests if bulk insert operations are allowed without limits',
		category: 'api',
		severity: 'medium',
		tags: ['api', 'bulk', 'dos'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'items', 'data'];
			const bulkAllowed: string[] = [];

			for (const table of tables) {
				try {
					// Try to insert multiple records at once
					const bulkData = Array(10).fill(null).map((_, i) => ({
						id: `00000000-0000-0000-0000-00000000000${i}`,
						test_bulk: true
					}));

					const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							Prefer: 'return=minimal'
						},
						body: JSON.stringify(bulkData)
					});

					if (response.ok || response.status === 201) {
						bulkAllowed.push(table);
						// Cleanup
						await fetch(`${ctx.targetUrl}/rest/v1/${table}?test_bulk=eq.true`, {
							method: 'DELETE',
							headers: {
								apikey: ctx.serviceKey,
								Authorization: `Bearer ${ctx.serviceKey}`
							}
						});
					}
				} catch {
					// Continue
				}
			}

			const breached = bulkAllowed.length > 0;

			return {
				attackId: 'api-bulk-insert',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Bulk insert allowed on ${bulkAllowed.length} tables - potential DoS vector`
					: 'Bulk operations properly restricted',
				details: {},
				evidence: breached ? { tables: bulkAllowed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-filter-bypass',
		name: 'Filter Operator Bypass',
		description: 'Tests for dangerous filter operators that could leak data',
		category: 'api',
		severity: 'high',
		tags: ['api', 'filter', 'data-leak'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const dangerousFilters = [
				{ filter: 'or=(id.gt.0,id.lt.0)', desc: 'OR bypass' },
				{ filter: 'not.id.is.null', desc: 'NOT NULL bypass' },
				{ filter: 'id.like.*', desc: 'LIKE wildcard' },
				{ filter: 'select=*,related_table(*)', desc: 'Embedding all' }
			];

			const bypassed: Array<{ filter: string; desc: string; count: number }> = [];

			for (const { filter, desc } of dangerousFilters) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/profiles?${filter}&limit=100`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 1) {
							bypassed.push({ filter, desc, count: data.length });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = bypassed.length > 0;

			return {
				attackId: 'api-filter-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${bypassed.length} filter operators can bypass restrictions`
					: 'Filter operators properly restricted',
				details: {},
				evidence: breached ? { bypasses: bypassed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-count-enumeration',
		name: 'Row Count Enumeration',
		description: 'Tests if exact row counts can be enumerated',
		category: 'api',
		severity: 'low',
		tags: ['api', 'enumeration', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'profiles', 'orders', 'payments'];
			const counts: Record<string, number> = {};

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=count`,
						{
							method: 'HEAD',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								Prefer: 'count=exact'
							}
						}
					);

					const contentRange = response.headers.get('content-range');
					if (contentRange) {
						const match = contentRange.match(/\/(\d+)/);
						if (match) {
							counts[table] = parseInt(match[1]);
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = Object.keys(counts).length > 0;

			return {
				attackId: 'api-count-enumeration',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Row counts exposed for ${Object.keys(counts).length} tables`
					: 'Row counts not exposed',
				details: {},
				evidence: breached ? { tableCounts: counts } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-rpc-exposure',
		name: 'RPC Function Enumeration',
		description: 'Tests if RPC functions are exposed and callable',
		category: 'api',
		severity: 'high',
		tags: ['api', 'rpc', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const commonFunctions = [
				'get_user',
				'get_users',
				'admin_get_users',
				'get_settings',
				'get_config',
				'execute_sql',
				'run_query',
				'delete_user',
				'update_role'
			];

			const accessible: Array<{ name: string; response: unknown }> = [];

			for (const fn of commonFunctions) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${fn}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({})
					});

					// If we get anything other than 404, function might exist
					if (response.status !== 404) {
						const data = await response.json().catch(() => ({ status: response.status }));
						accessible.push({ name: fn, response: data });
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'api-rpc-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} RPC functions potentially accessible`
					: 'No dangerous RPC functions exposed',
				details: {},
				evidence: breached ? { functions: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-embedding-abuse',
		name: 'Resource Embedding Abuse',
		description: 'Tests if foreign key relationships expose unauthorized data',
		category: 'api',
		severity: 'critical',
		tags: ['api', 'embedding', 'data-leak'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const embeddings = [
				{ table: 'posts', embed: 'author:users(*)' },
				{ table: 'comments', embed: 'user:users(*),post:posts(*)' },
				{ table: 'orders', embed: 'user:users(*)' },
				{ table: 'profiles', embed: 'user:auth.users(*)' }
			];

			const leaked: Array<{ query: string; data: unknown }> = [];

			for (const { table, embed } of embeddings) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*,${embed}&limit=5`,
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
							// Check if embedded data contains sensitive fields
							const hasEmbedded = data.some(row =>
								Object.values(row).some(v => v && typeof v === 'object')
							);
							if (hasEmbedded) {
								leaked.push({ query: `${table}?select=*,${embed}`, data: data.slice(0, 2) });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = leaked.length > 0;

			return {
				attackId: 'api-embedding-abuse',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${leaked.length} embedding queries leak related data`
					: 'Resource embedding properly restricted',
				details: {},
				evidence: breached ? { leaks: leaked } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'api-upsert-abuse',
		name: 'Upsert Privilege Escalation',
		description: 'Tests if upsert can be used to modify existing records',
		category: 'api',
		severity: 'critical',
		tags: ['api', 'upsert', 'privilege-escalation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'users', 'settings'];
			const vulnerable: string[] = [];

			for (const table of tables) {
				try {
					// Try to upsert with a known ID
					const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							Prefer: 'resolution=merge-duplicates,return=minimal'
						},
						body: JSON.stringify({
							id: '11111111-1111-1111-1111-111111111111',
							role: 'admin',
							is_admin: true
						})
					});

					if (response.ok || response.status === 201) {
						vulnerable.push(table);
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'api-upsert-abuse',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Upsert can modify records in ${vulnerable.length} tables`
					: 'Upsert operations properly restricted',
				details: {},
				evidence: breached ? { tables: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
