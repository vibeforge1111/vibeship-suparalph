/**
 * Vibe-Coder Attacks
 * Tests for common mistakes in AI-generated Supabase code
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Common patterns found in AI-generated code that create vulnerabilities
 */
export const vibecoderAttacks: AttackVector[] = [
	{
		id: 'vibecoder-service-key-exposed',
		name: 'Service Key in Client',
		description: 'Checks if service role key is accidentally exposed in client responses',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'secrets', 'misconfiguration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const endpoints = ['/', '/api/config', '/api/settings', '/.env', '/config.json'];
			const exposed: Array<{ endpoint: string; match: string }> = [];

			for (const endpoint of endpoints) {
				try {
					const response = await fetch(`${ctx.targetUrl.replace('/rest/v1', '')}${endpoint}`);
					const text = await response.text();

					// Check for service key patterns
					if (
						text.includes('service_role') ||
						text.includes('SUPABASE_SERVICE') ||
						(text.includes('eyJ') && text.length > 200)
					) {
						// Mask the key for evidence
						const match = text.substring(0, 100) + '...';
						exposed.push({ endpoint, match });
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'vibecoder-service-key-exposed',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'CRITICAL: Service key may be exposed in client-accessible endpoints!'
					: 'No service key exposure detected',
				details: {},
				evidence: breached ? { exposures: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-rls-disabled',
		name: 'RLS Completely Disabled',
		description: 'Common AI mistake: creating tables without enabling RLS',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'rls', 'disabled'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// AI often creates tables like this without RLS
			const aiTables = ['todos', 'posts', 'comments', 'likes', 'messages', 'notifications'];
			const noRls: string[] = [];

			for (const table of aiTables) {
				try {
					// Try to read all data - if we can, RLS is likely disabled
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=count`,
						{
							headers: {
								apikey: ctx.anonKey,
								Prefer: 'count=exact'
							}
						}
					);

					const countHeader = response.headers.get('content-range');
					if (countHeader && !countHeader.startsWith('0-0/0')) {
						// Table has data and we can see it - might be intentional but worth flagging
						const total = countHeader.split('/')[1];
						if (parseInt(total) > 0) {
							noRls.push(`${table} (${total} rows accessible)`);
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = noRls.length > 0;

			return {
				attackId: 'vibecoder-rls-disabled',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${noRls.length} common AI-generated tables accessible without auth`
					: 'No common unprotected tables found',
				details: {},
				evidence: breached ? { tables: noRls } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-client-side-auth',
		name: 'Client-Side Authorization',
		description: 'Tests for common pattern where auth is only checked client-side',
		category: 'vibecoder',
		severity: 'high',
		tags: ['vibecoder', 'auth', 'client-side'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// AI often implements admin checks only in frontend
			const adminEndpoints = [
				'/rest/v1/admin_users?select=*',
				'/rest/v1/settings?select=*',
				'/rest/v1/config?select=*',
				'/rest/v1/secrets?select=*'
			];

			const accessible: Array<{ endpoint: string; data: unknown }> = [];

			for (const endpoint of adminEndpoints) {
				try {
					const response = await fetch(`${ctx.targetUrl}${endpoint}`, {
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`
						}
					});

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 0) {
							accessible.push({ endpoint, data: data.slice(0, 2) });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'vibecoder-client-side-auth',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} admin-like endpoints accessible - client-side auth only?`
					: 'No client-side-only auth patterns detected',
				details: {},
				evidence: breached ? { endpoints: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-direct-db-urls',
		name: 'Direct Database URLs Exposed',
		description: 'AI sometimes hardcodes direct database connection strings',
		category: 'vibecoder',
		severity: 'critical',
		tags: ['vibecoder', 'database', 'connection-string'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const endpoints = [
				'/.env',
				'/api/env',
				'/config/database',
				'/.env.local',
				'/env.json'
			];

			const exposed: string[] = [];

			for (const endpoint of endpoints) {
				try {
					const baseUrl = ctx.targetUrl.replace('/rest/v1', '');
					const response = await fetch(`${baseUrl}${endpoint}`);
					const text = await response.text();

					// Check for postgres connection string patterns
					if (
						text.includes('postgresql://') ||
						text.includes('postgres://') ||
						text.includes('DATABASE_URL') ||
						text.includes('db.supabase.co')
					) {
						exposed.push(endpoint);
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'vibecoder-direct-db-urls',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Database connection strings may be exposed!'
					: 'No database URLs exposed',
				details: {},
				evidence: breached ? { endpoints: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'vibecoder-permissive-policy',
		name: 'Overly Permissive RLS Policy',
		description: 'AI often creates "true" policies that allow all access',
		category: 'vibecoder',
		severity: 'high',
		tags: ['vibecoder', 'rls', 'policy'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Tables commonly created with "enable RLS" but with "using (true)" policy
			const commonTables = ['profiles', 'users', 'posts', 'items'];
			const permissive: string[] = [];

			for (const table of commonTables) {
				try {
					// If anon can see all rows AND modify any row, policy is too permissive
					const readRes = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=id&limit=5`,
						{
							headers: { apikey: ctx.anonKey }
						}
					);

					if (readRes.ok) {
						const rows = await readRes.json();
						if (Array.isArray(rows) && rows.length > 1) {
							// Try to update a random row
							const testId = rows[0]?.id;
							if (testId) {
								const updateRes = await fetch(
									`${ctx.targetUrl}/rest/v1/${table}?id=eq.${testId}`,
									{
										method: 'PATCH',
										headers: {
											apikey: ctx.anonKey,
											'Content-Type': 'application/json',
											Prefer: 'return=minimal'
										},
										body: JSON.stringify({ updated_at: new Date().toISOString() })
									}
								);

								if (updateRes.ok || updateRes.status === 204) {
									permissive.push(table);
								}
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = permissive.length > 0;

			return {
				attackId: 'vibecoder-permissive-policy',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${permissive.length} tables have overly permissive RLS policies`
					: 'No overly permissive policies detected',
				details: {},
				evidence: breached ? { tables: permissive } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
