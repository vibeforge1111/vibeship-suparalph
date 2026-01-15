/**
 * Database Deep attacks
 * Tests for PostgreSQL deep/low-level vulnerabilities in Supabase
 */

import type { AttackVector } from '$lib/types/attacks';

export const databaseDeepAttacks: AttackVector[] = [
	{
		id: 'db-pg-dump-exposure',
		name: 'pg_dump Access',
		description: 'Check if pg_dump related functions are accessible',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to access pg_dump related views and functions
				const dumpEndpoints = [
					'pg_dump?select=*',
					'rpc/pg_dump',
					'pg_catalog.pg_dump?select=*'
				];

				for (const endpoint of dumpEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${endpoint}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (data && !data.code) {
							return {
								breached: true,
								status: 'breached',
								summary: `pg_dump access via ${endpoint}!`,
								evidence: { endpoint }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'pg_dump not accessible'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pg_dump protected' };
			}
		}
	},
	{
		id: 'db-copy-command-abuse',
		name: 'COPY Command Exploitation',
		description: 'Test for COPY command vulnerabilities via RPC',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to execute COPY via RPC
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/rpc/copy_to_file`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							table_name: 'users',
							file_path: '/tmp/dump.csv'
						}),
						signal: context.signal
					}
				);

				const copyAvailable = res.ok || (res.status !== 404 && res.status !== 403);

				return {
					breached: copyAvailable,
					status: copyAvailable ? 'breached' : 'secure',
					summary: copyAvailable
						? 'COPY command may be accessible via RPC'
						: 'COPY command properly restricted',
					evidence: copyAvailable ? { status: res.status } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'COPY command protected' };
			}
		}
	},
	{
		id: 'db-large-object-access',
		name: 'Large Object (LOB) Access',
		description: 'Test for PostgreSQL large object vulnerabilities',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Check for large object tables
				const lobTables = [
					'pg_largeobject',
					'pg_largeobject_metadata',
					'pg_catalog.pg_largeobject'
				];

				for (const table of lobTables) {
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
						return {
							breached: true,
							status: 'breached',
							summary: `Large objects exposed via ${table}`,
							evidence: { table, count: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Large objects not accessible'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'LOB protected' };
			}
		}
	},
	{
		id: 'db-advisory-lock-dos',
		name: 'Advisory Lock DoS',
		description: 'Test for advisory lock abuse',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to acquire advisory locks
				const lockRequests: Promise<Response>[] = [];

				for (let i = 0; i < 10; i++) {
					lockRequests.push(
						fetch(`${context.supabaseUrl}/rest/v1/rpc/pg_advisory_lock`, {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({ key: i }),
							signal: context.signal
						})
					);
				}

				const responses = await Promise.all(lockRequests);
				const successCount = responses.filter(r => r.ok).length;

				return {
					breached: successCount > 0,
					status: successCount > 0 ? 'breached' : 'secure',
					summary: successCount > 0
						? `Advisory locks acquirable: ${successCount}/10 - DoS possible`
						: 'Advisory locks properly restricted',
					evidence: successCount > 0 ? { locksAcquired: successCount } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Advisory locks protected' };
			}
		}
	},
	{
		id: 'db-wal-access',
		name: 'WAL (Write-Ahead Log) Access',
		description: 'Check if WAL-related functions are accessible',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const walEndpoints = [
					'rpc/pg_current_wal_lsn',
					'rpc/pg_walfile_name',
					'pg_replication_slots?select=*',
					'pg_stat_wal?select=*'
				];

				const accessible: string[] = [];

				for (const endpoint of walEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${endpoint}`,
						{
							method: endpoint.startsWith('rpc/') ? 'POST' : 'GET',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: endpoint.startsWith('rpc/') ? '{}' : undefined,
							signal: context.signal
						}
					);

					if (res.ok) {
						accessible.push(endpoint);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `WAL functions exposed: ${accessible.join(', ')}`
						: 'WAL functions protected',
					evidence: accessible.length > 0 ? { endpoints: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'WAL access protected' };
			}
		}
	},
	{
		id: 'db-connection-pooler-abuse',
		name: 'Connection Pooler Exhaustion',
		description: 'Test for connection pool exhaustion vulnerability',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to exhaust connection pool
				const requests: Promise<Response>[] = [];

				for (let i = 0; i < 50; i++) {
					requests.push(
						fetch(`${context.supabaseUrl}/rest/v1/rpc/pg_sleep`, {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({ seconds: 30 }),
							signal: context.signal
						})
					);
				}

				// Wait for first few responses
				const firstBatch = await Promise.race([
					Promise.all(requests.slice(0, 10)),
					new Promise<Response[]>(resolve => setTimeout(() => resolve([]), 5000))
				]);

				const acceptedSleep = firstBatch.some(r => r?.ok);

				return {
					breached: acceptedSleep,
					status: acceptedSleep ? 'breached' : 'secure',
					summary: acceptedSleep
						? 'pg_sleep accessible - connection exhaustion possible'
						: 'Sleep functions properly restricted',
					evidence: acceptedSleep ? { note: 'Long-running queries possible' } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Connection pool protected' };
			}
		}
	},
	{
		id: 'db-temp-table-abuse',
		name: 'Temporary Table Abuse',
		description: 'Test for temp table creation and abuse',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to create temp table via RPC
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/rpc/create_temp_table`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							name: 'temp_attack_test'
						}),
						signal: context.signal
					}
				);

				// Also check for pg_temp schema access
				const tempRes = await fetch(
					`${context.supabaseUrl}/rest/v1/pg_temp?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const tempAccessible = res.ok || tempRes.ok;

				return {
					breached: tempAccessible,
					status: tempAccessible ? 'breached' : 'secure',
					summary: tempAccessible
						? 'Temp table operations accessible'
						: 'Temp table operations restricted',
					evidence: tempAccessible ? { status: res.status } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Temp tables protected' };
			}
		}
	},
	{
		id: 'db-sequence-prediction',
		name: 'Sequence Value Prediction',
		description: 'Test if sequence values can be predicted/manipulated',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to access sequence information
				const seqEndpoints = [
					'pg_sequences?select=*',
					'information_schema.sequences?select=*'
				];

				for (const endpoint of seqEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${endpoint}`,
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
							summary: `${data.length} sequences exposed - IDs may be predictable`,
							evidence: {
								sequences: data.slice(0, 5).map((s: { sequencename?: string; sequence_name?: string }) =>
									s.sequencename || s.sequence_name
								)
							}
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Sequence information protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Sequences protected' };
			}
		}
	},
	{
		id: 'db-search-path-injection',
		name: 'Search Path Injection',
		description: 'Test for search_path manipulation vulnerabilities',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to set search_path via header or query
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/users?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`,
							'Prefer': 'params=single-object',
							'Content-Profile': 'public, pg_catalog, information_schema'
						},
						signal: context.signal
					}
				);

				// Check if different schema was used
				const profileUsed = res.headers.get('content-profile');

				return {
					breached: profileUsed !== null && profileUsed !== 'public',
					status: profileUsed !== 'public' ? 'breached' : 'secure',
					summary: profileUsed !== null && profileUsed !== 'public'
						? `Schema switching possible: ${profileUsed}`
						: 'Search path properly restricted',
					evidence: { contentProfile: profileUsed }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Search path protected' };
			}
		}
	}
];
