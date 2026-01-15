/**
 * Realtime Attacks
 * Tests for Supabase Realtime subscription vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Realtime Attack Vectors
 */
export const realtimeAttacks: AttackVector[] = [
	{
		id: 'realtime-unauthorized-subscribe',
		name: 'Unauthorized Channel Subscription',
		description: 'Tests if anonymous users can subscribe to realtime channels',
		category: 'realtime',
		severity: 'high',
		tags: ['realtime', 'subscribe', 'unauthorized'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Realtime uses WebSocket, but we can check the HTTP endpoint
			const channels = ['*', 'public', 'private', 'admin', 'users', 'orders'];
			const accessible: string[] = [];

			for (const channel of channels) {
				try {
					// Check if channel config is accessible
					const response = await fetch(
						`${ctx.targetUrl}/realtime/v1/channels/${channel}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						accessible.push(channel);
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'realtime-unauthorized-subscribe',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} realtime channels accessible without proper auth`
					: 'Realtime channels properly protected',
				details: {},
				evidence: breached ? { channels: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'realtime-broadcast-all',
		name: 'Broadcast to All Users',
		description: 'Tests if anonymous users can broadcast to channels',
		category: 'realtime',
		severity: 'high',
		tags: ['realtime', 'broadcast', 'spam'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const testMessage = {
				type: 'broadcast',
				event: 'supashield_test',
				payload: { test: true, timestamp: Date.now() }
			};

			try {
				const response = await fetch(
					`${ctx.targetUrl}/realtime/v1/broadcast`,
					{
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							channel: 'public',
							...testMessage
						})
					}
				);

				const canBroadcast = response.ok;

				return {
					attackId: 'realtime-broadcast-all',
					status: canBroadcast ? 'breached' : 'secure',
					breached: canBroadcast,
					summary: canBroadcast
						? 'Anonymous users can broadcast to realtime channels'
						: 'Broadcast properly restricted',
					details: {
						request: {
							method: 'POST',
							url: `${ctx.targetUrl}/realtime/v1/broadcast`
						},
						response: {
							status: response.status,
							statusText: response.statusText
						}
					},
					timestamp: new Date().toISOString(),
					duration: 0
				};
			} catch (err) {
				return {
					attackId: 'realtime-broadcast-all',
					status: 'error',
					breached: false,
					summary: `Error: ${err instanceof Error ? err.message : String(err)}`,
					details: { error: String(err) },
					timestamp: new Date().toISOString(),
					duration: 0
				};
			}
		}
	},
	{
		id: 'realtime-table-changes',
		name: 'Table Change Subscription',
		description: 'Tests if anonymous users can subscribe to table changes',
		category: 'realtime',
		severity: 'critical',
		tags: ['realtime', 'postgres-changes', 'data-leak'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'profiles', 'orders', 'payments', 'secrets'];
			const exposed: string[] = [];

			for (const table of tables) {
				try {
					// Try to subscribe to postgres changes
					const response = await fetch(
						`${ctx.targetUrl}/realtime/v1/subscribe`,
						{
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json'
							},
							body: JSON.stringify({
								type: 'postgres_changes',
								event: '*',
								schema: 'public',
								table: table
							})
						}
					);

					if (response.ok) {
						exposed.push(table);
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'realtime-table-changes',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${exposed.length} tables expose changes to anonymous users`
					: 'Table changes properly protected',
				details: {},
				evidence: breached ? { tables: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
