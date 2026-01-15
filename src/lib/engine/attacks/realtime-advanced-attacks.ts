/**
 * Realtime Advanced attacks
 * Deep exploitation of Supabase Realtime channels
 */

import type { AttackVector } from '$lib/types/attacks';

export const realtimeAdvancedAttacks: AttackVector[] = [
	{
		id: 'realtime-presence-abuse',
		name: 'Presence Channel User Enumeration',
		description: 'Enumerate users via presence channel state',
		category: 'realtime',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to access presence state via REST (limited test)
				const channels = ['presence', 'online-users', 'active-users', 'lobby'];
				const accessible: string[] = [];

				for (const channel of channels) {
					const res = await fetch(
						`${context.supabaseUrl}/realtime/v1/channels/${channel}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						accessible.push(channel);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Presence channels accessible: ${accessible.join(', ')}`
						: 'Presence channels protected',
					evidence: accessible.length > 0 ? { channels: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Presence channels not directly accessible' };
			}
		}
	},
	{
		id: 'realtime-broadcast-injection',
		name: 'Broadcast Message Injection',
		description: 'Test for broadcast message injection without auth',
		category: 'realtime',
		severity: 'high',
		async execute(context) {
			try {
				// Try to broadcast to a channel
				const res = await fetch(
					`${context.supabaseUrl}/realtime/v1/api/broadcast`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							channel: 'test-channel',
							event: 'test',
							payload: { message: 'supashield-test' }
						}),
						signal: context.signal
					}
				);

				const canBroadcast = res.ok || res.status === 202;

				return {
					breached: canBroadcast,
					status: canBroadcast ? 'breached' : 'secure',
					summary: canBroadcast
						? 'Can broadcast messages without proper auth!'
						: 'Broadcast properly restricted',
					evidence: canBroadcast ? { status: res.status } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Broadcast endpoint not accessible' };
			}
		}
	},
	{
		id: 'realtime-channel-enumeration',
		name: 'Channel Enumeration',
		description: 'Enumerate active realtime channels',
		category: 'realtime',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to list channels
				const res = await fetch(
					`${context.supabaseUrl}/realtime/v1/api/channels`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasChannels = Array.isArray(data) || (data && data.channels);

				return {
					breached: hasChannels,
					status: hasChannels ? 'breached' : 'secure',
					summary: hasChannels
						? `Channel listing exposed: ${Array.isArray(data) ? data.length : 'unknown'} channels`
						: 'Channel listing protected',
					evidence: hasChannels ? data : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Channel listing not accessible' };
			}
		}
	},
	{
		id: 'realtime-postgres-changes-bypass',
		name: 'Postgres Changes Filter Bypass',
		description: 'Test for bypassing postgres_changes RLS',
		category: 'realtime',
		severity: 'critical',
		async execute(context) {
			try {
				// Check if postgres changes can be subscribed without proper RLS
				const res = await fetch(
					`${context.supabaseUrl}/realtime/v1/websocket?apikey=${context.anonKey}&vsn=1.0.0`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`,
							'Upgrade': 'websocket',
							'Connection': 'Upgrade'
						},
						signal: context.signal
					}
				);

				// Check if websocket upgrade would succeed
				const wsAvailable = res.status === 101 || res.status === 426 || res.headers.get('upgrade');

				return {
					breached: false,
					status: 'secure',
					summary: wsAvailable
						? 'Realtime WebSocket available - requires client-side testing for RLS bypass'
						: 'Realtime endpoint status: ' + res.status,
					details: { note: 'Full postgres_changes bypass requires WebSocket connection' }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test postgres_changes' };
			}
		}
	},
	{
		id: 'realtime-rate-limit',
		name: 'Realtime Rate Limit Bypass',
		description: 'Test if realtime has rate limiting',
		category: 'realtime',
		severity: 'medium',
		async execute(context) {
			try {
				const requests = [];
				const startTime = Date.now();

				// Send rapid requests to realtime
				for (let i = 0; i < 20; i++) {
					requests.push(
						fetch(`${context.supabaseUrl}/realtime/v1/api/broadcast`, {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({
								channel: `test-${i}`,
								event: 'ping',
								payload: {}
							}),
							signal: context.signal
						})
					);
				}

				const responses = await Promise.all(requests);
				const elapsed = Date.now() - startTime;

				const rateLimited = responses.some(r => r.status === 429);
				const allSucceeded = responses.every(r => r.ok || r.status === 202);

				return {
					breached: allSucceeded && !rateLimited,
					status: rateLimited ? 'secure' : allSucceeded ? 'breached' : 'secure',
					summary: rateLimited
						? 'Rate limiting active on realtime'
						: allSucceeded
							? `No rate limiting: ${requests.length} requests in ${elapsed}ms`
							: 'Realtime requests blocked',
					evidence: { requestCount: requests.length, elapsed, rateLimited }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test rate limiting' };
			}
		}
	},
	{
		id: 'realtime-token-exposure',
		name: 'Realtime Token in URL',
		description: 'Check if sensitive tokens appear in WebSocket URL',
		category: 'realtime',
		severity: 'medium',
		async execute(context) {
			// Check standard realtime URL patterns
			const realtimeUrl = `${context.supabaseUrl}/realtime/v1/websocket?apikey=${context.anonKey}&vsn=1.0.0`;

			// Analyze URL for sensitive data
			const hasApiKeyInUrl = realtimeUrl.includes('apikey=');
			const hasTokenInUrl = realtimeUrl.includes('token=') || realtimeUrl.includes('access_token=');

			return {
				breached: hasApiKeyInUrl || hasTokenInUrl,
				status: hasApiKeyInUrl || hasTokenInUrl ? 'breached' : 'secure',
				summary: hasApiKeyInUrl
					? 'API key exposed in WebSocket URL (may appear in logs)'
					: 'Tokens not in URL query params',
				evidence: { urlPattern: 'apikey in query string' }
			};
		}
	},
	{
		id: 'realtime-private-channel-access',
		name: 'Private Channel Access',
		description: 'Test access to private/restricted channels',
		category: 'realtime',
		severity: 'high',
		async execute(context) {
			try {
				const privateChannels = [
					'private:admin',
					'private:system',
					'admin-notifications',
					'internal-events',
					'system:alerts'
				];

				const accessible: string[] = [];

				for (const channel of privateChannels) {
					const res = await fetch(
						`${context.supabaseUrl}/realtime/v1/api/broadcast`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({
								channel,
								event: 'test',
								payload: {}
							}),
							signal: context.signal
						}
					);

					if (res.ok || res.status === 202) {
						accessible.push(channel);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Can access private channels: ${accessible.join(', ')}`
						: 'Private channels properly restricted',
					evidence: accessible.length > 0 ? { channels: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Private channels not accessible' };
			}
		}
	}
];
