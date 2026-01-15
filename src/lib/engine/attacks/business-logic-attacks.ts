/**
 * Business Logic Attacks
 * Tests for IDOR, race conditions, state manipulation
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Business Logic Attack Vectors
 */
export const businessLogicAttacks: AttackVector[] = [
	{
		id: 'logic-idor-uuid',
		name: 'IDOR via UUID Manipulation',
		description: 'Tests for Insecure Direct Object Reference by modifying UUIDs',
		category: 'rls',
		severity: 'critical',
		tags: ['idor', 'uuid', 'access-control'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['orders', 'invoices', 'documents', 'messages', 'tickets'];
			const testUuids = [
				'00000000-0000-0000-0000-000000000001',
				'12345678-1234-1234-1234-123456789012',
				'ffffffff-ffff-ffff-ffff-ffffffffffff'
			];

			const accessible: Array<{ table: string; uuid: string; fields: string[] }> = [];

			for (const table of tables) {
				for (const uuid of testUuids) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?id=eq.${uuid}&select=*`,
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
								accessible.push({
									table,
									uuid,
									fields: Object.keys(data[0])
								});
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'logic-idor-uuid',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `IDOR: Can access ${accessible.length} objects via UUID guessing`
					: 'UUID-based IDOR not detected',
				details: {},
				evidence: breached ? { objects: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-idor-sequential',
		name: 'IDOR via Sequential ID',
		description: 'Tests for IDOR using sequential/predictable IDs',
		category: 'rls',
		severity: 'critical',
		tags: ['idor', 'sequential', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['orders', 'users', 'invoices', 'tickets'];
			const accessible: Array<{ table: string; ids: number[] }> = [];

			for (const table of tables) {
				const foundIds: number[] = [];
				for (let id = 1; id <= 20; id++) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/rest/v1/${table}?id=eq.${id}&select=*`,
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
								foundIds.push(id);
							}
						}
					} catch {
						// Continue
					}
				}

				if (foundIds.length > 0) {
					accessible.push({ table, ids: foundIds });
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'logic-idor-sequential',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Sequential IDOR: ${accessible.reduce((sum, t) => sum + t.ids.length, 0)} objects accessible`
					: 'Sequential ID IDOR not detected',
				details: {},
				evidence: breached ? { tables: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-race-condition',
		name: 'Race Condition Detection',
		description: 'Tests for race conditions in concurrent operations',
		category: 'api',
		severity: 'high',
		tags: ['race', 'concurrency', 'timing'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Test for race condition in update operations
			const testTable = 'profiles';
			let raceDetected = false;

			try {
				// Send multiple concurrent updates
				const promises = Array(10).fill(null).map((_, i) =>
					fetch(`${ctx.targetUrl}/rest/v1/${testTable}?id=eq.test-race`, {
						method: 'PATCH',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							Prefer: 'return=representation'
						},
						body: JSON.stringify({ counter: i })
					})
				);

				const responses = await Promise.allSettled(promises);
				const successfulUpdates = responses.filter(
					r => r.status === 'fulfilled' && (r.value as Response).ok
				);

				// If all updates succeeded without conflict, might have race condition
				if (successfulUpdates.length > 5) {
					raceDetected = true;
				}
			} catch {
				// Continue
			}

			return {
				attackId: 'logic-race-condition',
				status: raceDetected ? 'breached' : 'secure',
				breached: raceDetected,
				summary: raceDetected
					? 'Potential race condition - no optimistic locking detected'
					: 'Race condition test completed',
				details: {},
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-mass-assignment',
		name: 'Mass Assignment Vulnerability',
		description: 'Tests if protected fields can be modified via mass assignment',
		category: 'api',
		severity: 'critical',
		tags: ['mass-assignment', 'privilege', 'escalation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'users', 'accounts'];
			const protectedFields = [
				{ field: 'role', value: 'admin' },
				{ field: 'is_admin', value: true },
				{ field: 'permissions', value: ['admin', 'superuser'] },
				{ field: 'verified', value: true },
				{ field: 'email_verified', value: true },
				{ field: 'subscription_tier', value: 'enterprise' },
				{ field: 'credits', value: 999999 }
			];

			const vulnerable: Array<{ table: string; field: string }> = [];

			for (const table of tables) {
				for (const { field, value } of protectedFields) {
					try {
						const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=representation'
							},
							body: JSON.stringify({
								id: 'mass-assignment-test',
								[field]: value
							})
						});

						if (response.ok || response.status === 201) {
							const data = await response.json();
							if (Array.isArray(data) && data[0]?.[field] === value) {
								vulnerable.push({ table, field });
							}
							// Cleanup
							await fetch(
								`${ctx.targetUrl}/rest/v1/${table}?id=eq.mass-assignment-test`,
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
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'logic-mass-assignment',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Mass assignment: ${vulnerable.length} protected fields writable!`
					: 'Mass assignment properly blocked',
				details: {},
				evidence: breached ? { fields: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-state-manipulation',
		name: 'State Manipulation Attack',
		description: 'Tests if workflow states can be manipulated',
		category: 'api',
		severity: 'high',
		tags: ['state', 'workflow', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['orders', 'tickets', 'subscriptions', 'payments'];
			const stateFields = ['status', 'state', 'workflow_state', 'payment_status'];
			const privilegedStates = ['completed', 'paid', 'approved', 'verified', 'active'];

			const manipulated: Array<{ table: string; field: string; state: string }> = [];

			for (const table of tables) {
				for (const field of stateFields) {
					for (const state of privilegedStates) {
						try {
							const response = await fetch(
								`${ctx.targetUrl}/rest/v1/${table}?id=eq.test-state`,
								{
									method: 'PATCH',
									headers: {
										apikey: ctx.anonKey,
										Authorization: `Bearer ${ctx.anonKey}`,
										'Content-Type': 'application/json',
										Prefer: 'return=representation'
									},
									body: JSON.stringify({ [field]: state })
								}
							);

							if (response.ok) {
								const data = await response.json();
								if (Array.isArray(data) && data[0]?.[field] === state) {
									manipulated.push({ table, field, state });
								}
							}
						} catch {
							// Continue
						}
					}
				}
			}

			const breached = manipulated.length > 0;

			return {
				attackId: 'logic-state-manipulation',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `State manipulation: ${manipulated.length} states can be changed`
					: 'State transitions properly controlled',
				details: {},
				evidence: breached ? { manipulations: manipulated } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-price-manipulation',
		name: 'Price/Amount Manipulation',
		description: 'Tests if prices or amounts can be manipulated client-side',
		category: 'api',
		severity: 'critical',
		tags: ['price', 'financial', 'manipulation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['orders', 'cart_items', 'line_items', 'invoices'];
			const priceFields = ['price', 'amount', 'total', 'unit_price', 'subtotal'];

			const manipulated: Array<{ table: string; field: string }> = [];

			for (const table of tables) {
				for (const field of priceFields) {
					try {
						// Try to set price to 0 or negative
						const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=representation'
							},
							body: JSON.stringify({
								[field]: 0.01, // Suspiciously low price
								quantity: 1
							})
						});

						if (response.ok || response.status === 201) {
							const data = await response.json();
							if (Array.isArray(data) && data[0]?.[field] <= 0.01) {
								manipulated.push({ table, field });
							}
							// Cleanup
							await fetch(
								`${ctx.targetUrl}/rest/v1/${table}?${field}=eq.0.01`,
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
			}

			const breached = manipulated.length > 0;

			return {
				attackId: 'logic-price-manipulation',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: Price manipulation possible in ${manipulated.length} cases!`
					: 'Price fields properly protected',
				details: {},
				evidence: breached ? { fields: manipulated } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'logic-quantity-abuse',
		name: 'Quantity/Limit Abuse',
		description: 'Tests for negative quantities or limit bypasses',
		category: 'api',
		severity: 'high',
		tags: ['quantity', 'limit', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['orders', 'cart_items', 'redemptions'];
			const abusiveValues = [-1, -100, 0, 999999999, 2147483647];

			const accepted: Array<{ table: string; value: number }> = [];

			for (const table of tables) {
				for (const value of abusiveValues) {
					try {
						const response = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=representation'
							},
							body: JSON.stringify({ quantity: value })
						});

						if (response.ok || response.status === 201) {
							const data = await response.json();
							if (Array.isArray(data) && data[0]?.quantity === value) {
								accepted.push({ table, value });
							}
						}
					} catch {
						// Continue
					}
				}
			}

			const breached = accepted.some(a => a.value < 0 || a.value > 10000);

			return {
				attackId: 'logic-quantity-abuse',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Invalid quantities accepted in ${accepted.length} cases`
					: 'Quantity validation properly enforced',
				details: {},
				evidence: accepted.length > 0 ? { accepted } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
