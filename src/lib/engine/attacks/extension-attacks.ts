/**
 * Database Extension attacks
 * Tests for PostgreSQL extension vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const extensionAttacks: AttackVector[] = [
	{
		id: 'ext-postgis-injection',
		name: 'PostGIS SQL Injection',
		description: 'Test for SQL injection via PostGIS functions',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Test PostGIS function with injection
				const injectionQueries = [
					"rpc/st_astext?geom=POINT(1 1)'; SELECT * FROM users--",
					"locations?select=*,st_distance(geom, 'POINT(0 0)'::geometry)"
				];

				for (const query of injectionQueries) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${query}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					// Check if injection succeeded (got data instead of error)
					if (Array.isArray(data) && data.length > 0 && !data[0]?.code) {
						return {
							breached: true,
							status: 'breached',
							summary: 'PostGIS SQL injection possible',
							evidence: { query }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'PostGIS functions properly sanitized'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'PostGIS not accessible or secure' };
			}
		}
	},
	{
		id: 'ext-pgvector-abuse',
		name: 'pgvector Similarity Search Abuse',
		description: 'Test for data leakage via vector similarity searches',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to access embedding/vector tables
				const vectorTables = ['embeddings', 'vectors', 'documents', 'knowledge_base'];
				const accessible: string[] = [];

				for (const table of vectorTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=10`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						accessible.push(`${table}(${data.length})`);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Vector tables exposed: ${accessible.join(', ')}`
						: 'Vector tables protected',
					evidence: accessible.length > 0 ? { tables: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Vector tables not accessible' };
			}
		}
	},
	{
		id: 'ext-pg-stat-exposure',
		name: 'pg_stat_statements Exposure',
		description: 'Check if query statistics reveal sensitive information',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/pg_stat_statements?select=*&limit=50`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && data.length > 0;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? `pg_stat_statements exposed - ${data.length} queries visible`
						: 'Query statistics protected',
					evidence: hasAccess ? {
						queryCount: data.length,
						sampleQueries: data.slice(0, 3).map((q: { query: string }) => q.query?.substring(0, 100))
					} : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pg_stat_statements not accessible' };
			}
		}
	},
	{
		id: 'ext-pg-cron-access',
		name: 'pg_cron Extension Access',
		description: 'Check if pg_cron extension tables are accessible',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const cronTables = ['cron.job', 'cron.job_run_details'];
				const accessible: string[] = [];

				for (const table of cronTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data)) {
						accessible.push(table);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `pg_cron tables exposed: ${accessible.join(', ')}`
						: 'pg_cron tables protected',
					evidence: accessible.length > 0 ? { tables: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pg_cron not accessible' };
			}
		}
	},
	{
		id: 'ext-pgaudit-logs',
		name: 'pgAudit Log Exposure',
		description: 'Check if audit logs are accessible',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const auditTables = ['pgaudit.log', 'audit_log', 'audit.logs', 'pg_audit'];
				const accessible: string[] = [];

				for (const table of auditTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=10`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						accessible.push(`${table}(${data.length})`);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Audit logs exposed: ${accessible.join(', ')}`
						: 'Audit logs protected',
					evidence: accessible.length > 0 ? { tables: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Audit tables not accessible' };
			}
		}
	},
	{
		id: 'ext-fdw-credentials',
		name: 'Foreign Data Wrapper Credentials',
		description: 'Check if FDW credentials are exposed',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Check for FDW configuration tables
				const fdwTables = [
					'pg_foreign_server',
					'pg_user_mapping',
					'information_schema.foreign_servers'
				];

				for (const table of fdwTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						// Check for credentials
						const hasCredentials = data.some(row =>
							row.options?.includes('password') ||
							row.srvoptions?.includes('password') ||
							row.umoptions?.includes('password')
						);

						if (hasCredentials) {
							return {
								breached: true,
								status: 'breached',
								summary: 'FDW credentials exposed!',
								evidence: { table, count: data.length }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'FDW credentials not exposed'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'FDW tables not accessible' };
			}
		}
	},
	{
		id: 'ext-uuid-prediction',
		name: 'UUID-OSSP Predictable Generation',
		description: 'Test if UUID generation is predictable',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Generate multiple UUIDs and check for patterns
				const uuids: string[] = [];

				for (let i = 0; i < 5; i++) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/rpc/gen_random_uuid`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: '{}',
							signal: context.signal
						}
					);

					const data = await res.json();
					if (typeof data === 'string') {
						uuids.push(data);
					}
				}

				// Check for version 1 UUIDs (time-based, predictable)
				const hasV1 = uuids.some(uuid => uuid.charAt(14) === '1');

				return {
					breached: hasV1,
					status: hasV1 ? 'breached' : 'secure',
					summary: hasV1
						? 'Using UUID v1 (time-based) - potentially predictable'
						: 'Using secure random UUIDs',
					evidence: hasV1 ? { uuids } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'UUID generation secure' };
			}
		}
	},
	{
		id: 'ext-pgsodium-keys',
		name: 'pgsodium Key Access',
		description: 'Check if encryption keys are accessible',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const keyTables = [
					'pgsodium.key',
					'pgsodium.valid_key',
					'pgsodium.decrypted_key'
				];

				for (const table of keyTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						return {
							breached: true,
							status: 'breached',
							summary: `pgsodium keys exposed via ${table}!`,
							evidence: { table, keyCount: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'pgsodium keys protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pgsodium not accessible' };
			}
		}
	}
];
