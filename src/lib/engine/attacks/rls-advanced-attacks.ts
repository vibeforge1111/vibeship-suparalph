/**
 * Advanced RLS Attacks
 * Tests for sophisticated RLS bypass techniques
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Advanced RLS Attack Vectors
 */
export const rlsAdvancedAttacks: AttackVector[] = [
	{
		id: 'rls-horizontal-privilege-escalation',
		name: 'Horizontal Privilege Escalation',
		description: 'Tests if users can access other users data by manipulating user_id',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'horizontal', 'escalation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'users', 'orders', 'documents', 'settings'];
			const testUserIds = [
				'00000000-0000-0000-0000-000000000001',
				'11111111-1111-1111-1111-111111111111',
				'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
			];

			const vulnerable: Array<{ table: string; userId: string }> = [];

			for (const table of tables) {
				for (const userId of testUserIds) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?user_id=eq.${userId}&select=*`,
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
								vulnerable.push({ table, userId });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'rls-horizontal-privilege-escalation',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Can access other users' data in ${vulnerable.length} cases`
					: 'Horizontal access properly restricted',
				details: {},
				evidence: breached ? { cases: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'rls-update-other-users',
		name: 'Update Other Users Data',
		description: 'Tests if users can modify data belonging to other users',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'update', 'escalation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'settings', 'preferences'];
			const vulnerable: string[] = [];

			for (const table of tables) {
				try {
					// Try to update records belonging to other users
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?user_id=neq.00000000-0000-0000-0000-000000000000`,
						{
							method: 'PATCH',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=minimal'
							},
							body: JSON.stringify({ updated_at: new Date().toISOString() })
						}
					);

					if (response.ok || response.status === 204) {
						vulnerable.push(table);
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'rls-update-other-users',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Can update other users' data in ${vulnerable.length} tables!`
					: 'Update operations properly restricted',
				details: {},
				evidence: breached ? { tables: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'rls-insert-as-other-user',
		name: 'Insert As Other User',
		description: 'Tests if data can be inserted with arbitrary user_id',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'insert', 'impersonation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['posts', 'comments', 'messages', 'activities'];
			const fakeUserId = '99999999-9999-9999-9999-999999999999';
			const vulnerable: string[] = [];

			for (const table of tables) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							Prefer: 'return=minimal'
						},
						body: JSON.stringify({
							user_id: fakeUserId,
							content: 'supashield_impersonation_test',
							created_at: new Date().toISOString()
						})
					});

					if (response.ok || response.status === 201) {
						vulnerable.push(table);
						// Cleanup
						await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?content=eq.supashield_impersonation_test`,
							{
								method: 'DELETE',
								headers: {
									apikey: ctx.serviceKey,
									Authorization: `Bearer ${ctx.serviceKey}`
								}
							}
						);
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'rls-insert-as-other-user',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Can insert data as arbitrary users in ${vulnerable.length} tables`
					: 'User impersonation via insert blocked',
				details: {},
				evidence: breached ? { tables: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'rls-joined-table-bypass',
		name: 'RLS Bypass via Table Joins',
		description: 'Tests if RLS can be bypassed through foreign key relationships',
		category: 'rls',
		severity: 'high',
		tags: ['rls', 'joins', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const joinQueries = [
				{ base: 'posts', join: 'users', select: 'posts(*,users(*))' },
				{ base: 'comments', join: 'profiles', select: 'comments(*,author:profiles(*))' },
				{ base: 'orders', join: 'users', select: 'orders(*,customer:users(*))' },
				{ base: 'messages', join: 'profiles', select: 'messages(*,sender:profiles(*),receiver:profiles(*))' }
			];

			const leaks: Array<{ query: string; leakedFields: string[] }> = [];

			for (const { base, select } of joinQueries) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${base}?select=${encodeURIComponent(select)}&limit=5`,
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
							// Check if joined data contains sensitive fields
							const sensitiveFields = ['email', 'phone', 'password', 'secret', 'token', 'api_key'];
							const leakedFields: string[] = [];

							const checkObject = (obj: unknown, path: string = ''): void => {
								if (obj && typeof obj === 'object') {
									for (const [key, value] of Object.entries(obj)) {
										const fullPath = path ? `${path}.${key}` : key;
										if (sensitiveFields.some(f => key.toLowerCase().includes(f))) {
											if (value !== null && value !== undefined) {
												leakedFields.push(fullPath);
											}
										}
										if (typeof value === 'object') {
											checkObject(value, fullPath);
										}
									}
								}
							};

							data.forEach((row: unknown) => checkObject(row));

							if (leakedFields.length > 0) {
								leaks.push({ query: `${base}?select=${select}`, leakedFields });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = leaks.length > 0;

			return {
				attackId: 'rls-joined-table-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${leaks.length} join queries leak sensitive data`
					: 'Table joins properly restricted',
				details: {},
				evidence: breached ? { leaks } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'rls-soft-delete-bypass',
		name: 'Soft Delete Data Access',
		description: 'Tests if soft-deleted records can still be accessed',
		category: 'rls',
		severity: 'medium',
		tags: ['rls', 'soft-delete', 'data-leak'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'posts', 'comments', 'orders'];
			const deletedFields = ['deleted_at', 'is_deleted', 'deleted', 'archived', 'archived_at'];
			const exposed: Array<{ table: string; field: string; count: number }> = [];

			for (const table of tables) {
				for (const field of deletedFields) {
					try {
						// Try to access deleted records
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?${field}=not.is.null&select=*&limit=10`,
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
								exposed.push({ table, field, count: data.length });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'rls-soft-delete-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Soft-deleted data accessible in ${exposed.length} cases`
					: 'Soft-deleted data properly hidden',
				details: {},
				evidence: breached ? { exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'rls-aggregate-data-leak',
		name: 'Aggregate Function Data Leak',
		description: 'Tests if aggregate functions can leak restricted data counts',
		category: 'rls',
		severity: 'medium',
		tags: ['rls', 'aggregate', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'orders', 'payments', 'messages'];
			const aggregates: Array<{ table: string; count: number }> = [];

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
						if (match && parseInt(match[1]) > 0) {
							aggregates.push({ table, count: parseInt(match[1]) });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = aggregates.length > 2; // Some count exposure is normal

			return {
				attackId: 'rls-aggregate-data-leak',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Row counts exposed for ${aggregates.length} tables`
					: 'Aggregate data properly restricted',
				details: {},
				evidence: aggregates.length > 0 ? { aggregates } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
