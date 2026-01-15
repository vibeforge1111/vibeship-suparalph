/**
 * Denial of Service Attacks
 * Tests for resource exhaustion and DoS vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * DoS Attack Vectors
 */
export const dosAttacks: AttackVector[] = [
	{
		id: 'dos-query-complexity',
		name: 'Query Complexity Attack',
		description: 'Tests if complex nested queries are allowed',
		category: 'api',
		severity: 'medium',
		tags: ['dos', 'query', 'complexity'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Build a deeply nested query
			const deepEmbed = 'posts(comments(author:profiles(posts(comments(author:profiles(*))))))';

			try {
				const response = await fetch(
					`${ctx.targetUrl}/rest/v1/profiles?select=*,${deepEmbed}&limit=10`,
					{
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`
						}
					}
				);

				// If deeply nested query succeeds, it's a DoS risk
				if (response.ok) {
					return {
						attackId: 'dos-query-complexity',
						status: 'breached',
						breached: true,
						summary: 'Deep nested queries allowed - DoS risk via query complexity',
						details: { queryDepth: 6 },
						timestamp: new Date().toISOString(),
						duration: 0
					};
				}
			} catch {
				// Continue
			}

			return {
				attackId: 'dos-query-complexity',
				status: 'secure',
				breached: false,
				summary: 'Query depth properly limited',
				details: {},
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'dos-large-response',
		name: 'Large Response Attack',
		description: 'Tests if large data responses are limited',
		category: 'api',
		severity: 'medium',
		tags: ['dos', 'response', 'size'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['profiles', 'posts', 'logs', 'events'];
			let largeResponseAllowed = false;
			let maxRecords = 0;

			for (const table of tables) {
				try {
					// Try to request a huge number of records
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=100000`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 1000) {
							largeResponseAllowed = true;
							maxRecords = Math.max(maxRecords, data.length);
						}
					}
				} catch {
					// Continue
				}
			}

			return {
				attackId: 'dos-large-response',
				status: largeResponseAllowed ? 'breached' : 'secure',
				breached: largeResponseAllowed,
				summary: largeResponseAllowed
					? `Large responses allowed (${maxRecords}+ records) - DoS risk`
					: 'Response size properly limited',
				details: { maxRecords },
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'dos-batch-operations',
		name: 'Batch Operation Abuse',
		description: 'Tests if batch operations have limits',
		category: 'api',
		severity: 'medium',
		tags: ['dos', 'batch', 'bulk'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Try to insert many records at once
			const bulkData = Array(1000).fill(null).map((_, i) => ({
				id: `dos-test-${i}`,
				name: `Test ${i}`,
				created_at: new Date().toISOString()
			}));

			try {
				const response = await fetch(`${ctx.targetUrl}/rest/v1/profiles`, {
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
					// Cleanup
					await fetch(
						`${ctx.targetUrl}/rest/v1/profiles?id=like.dos-test-*`,
						{
							method: 'DELETE',
							headers: {
								apikey: ctx.serviceKey,
								Authorization: `Bearer ${ctx.serviceKey}`
							}
						}
					);

					return {
						attackId: 'dos-batch-operations',
						status: 'breached',
						breached: true,
						summary: 'Batch insert of 1000 records allowed - DoS risk',
						details: { recordsInserted: 1000 },
						timestamp: new Date().toISOString(),
						duration: 0
					};
				}
			} catch {
				// Continue
			}

			return {
				attackId: 'dos-batch-operations',
				status: 'secure',
				breached: false,
				summary: 'Batch operations properly limited',
				details: {},
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'dos-regex-redos',
		name: 'ReDoS via Pattern Matching',
		description: 'Tests for Regular Expression DoS via pattern operators',
		category: 'api',
		severity: 'high',
		tags: ['dos', 'regex', 'redos'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// ReDoS payload - exponential backtracking
			const redosPayloads = [
				'(a+)+$',
				'([a-zA-Z]+)*',
				'(a|aa)+',
				'(.*a){x}' // Where x is a large number
			];

			let vulnerable = false;

			for (const pattern of redosPayloads) {
				try {
					const startTime = Date.now();
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/profiles?name=match.${encodeURIComponent(pattern)}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					const duration = Date.now() - startTime;

					// If request took unusually long, might be ReDoS
					if (duration > 5000) {
						vulnerable = true;
						break;
					}
				} catch {
					// Continue
				}
			}

			return {
				attackId: 'dos-regex-redos',
				status: vulnerable ? 'breached' : 'secure',
				breached: vulnerable,
				summary: vulnerable
					? 'ReDoS vulnerability detected - slow regex processing'
					: 'Pattern matching properly constrained',
				details: {},
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'dos-connection-exhaustion',
		name: 'Connection Pool Exhaustion',
		description: 'Tests if connection limits can be exhausted',
		category: 'database',
		severity: 'high',
		tags: ['dos', 'connection', 'exhaustion'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Send many concurrent long-running requests
			const concurrentRequests = 50;
			let failedRequests = 0;

			const promises = Array(concurrentRequests).fill(null).map(() =>
				fetch(`${ctx.targetUrl}/rest/v1/profiles?select=*&limit=1000`, {
					headers: {
						apikey: ctx.anonKey,
						Authorization: `Bearer ${ctx.anonKey}`
					}
				}).catch(() => null)
			);

			const results = await Promise.allSettled(promises);

			failedRequests = results.filter(
				r => r.status === 'rejected' ||
					(r.status === 'fulfilled' && (!r.value || !(r.value as Response).ok))
			).length;

			// If many requests failed, connection pool might be vulnerable
			const breached = failedRequests < 5; // All succeeded = no limits

			return {
				attackId: 'dos-connection-exhaustion',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${concurrentRequests} concurrent requests accepted - connection exhaustion risk`
					: `${failedRequests}/${concurrentRequests} requests limited`,
				details: { concurrentRequests, failedRequests },
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'dos-storage-quota',
		name: 'Storage Quota Abuse',
		description: 'Tests if storage quotas are enforced',
		category: 'storage',
		severity: 'medium',
		tags: ['dos', 'storage', 'quota'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const buckets = ['uploads', 'public', 'files'];
			let quotaEnforced = true;

			for (const bucket of buckets) {
				try {
					// Try to upload a reasonably large file
					const largeContent = 'x'.repeat(10 * 1024 * 1024); // 10MB

					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/${bucket}/dos-test-large-file`,
						{
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/octet-stream'
							},
							body: largeContent
						}
					);

					if (response.ok) {
						quotaEnforced = false;
						// Cleanup
						await fetch(
							`${ctx.targetUrl}/storage/v1/object/${bucket}/dos-test-large-file`,
							{
								method: 'DELETE',
								headers: {
									apikey: ctx.serviceKey,
									Authorization: `Bearer ${ctx.serviceKey}`
								}
							}
						);
						break;
					}
				} catch {
					// Continue - might be blocked by size limit
				}
			}

			return {
				attackId: 'dos-storage-quota',
				status: quotaEnforced ? 'secure' : 'breached',
				breached: !quotaEnforced,
				summary: quotaEnforced
					? 'Storage quotas properly enforced'
					: 'Large file uploads accepted - storage quota abuse risk',
				details: {},
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
