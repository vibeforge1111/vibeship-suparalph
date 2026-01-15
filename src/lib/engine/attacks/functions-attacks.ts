/**
 * Edge Functions Attacks
 * Tests for Supabase Edge Functions vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Functions Attack Vectors
 */
export const functionsAttacks: AttackVector[] = [
	{
		id: 'functions-no-auth',
		name: 'Unauthenticated Function Access',
		description: 'Tests if edge functions can be called without authentication',
		category: 'functions',
		severity: 'high',
		tags: ['functions', 'auth', 'public'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const commonFunctions = [
				'hello-world',
				'api',
				'webhook',
				'process',
				'sync',
				'notify',
				'send-email',
				'stripe-webhook'
			];

			const accessible: Array<{ name: string; response: unknown }> = [];

			for (const fn of commonFunctions) {
				try {
					// Try without any auth
					const response = await fetch(`${ctx.targetUrl}/functions/v1/${fn}`, {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ test: true })
					});

					if (response.ok) {
						const data = await response.json().catch(() => ({}));
						accessible.push({ name: fn, response: data });
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'functions-no-auth',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} functions accessible without authentication`
					: 'Functions properly require authentication',
				details: {},
				evidence: breached ? { functions: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'functions-injection',
		name: 'Command/SQL Injection',
		description: 'Tests for injection vulnerabilities in function parameters',
		category: 'functions',
		severity: 'critical',
		tags: ['functions', 'injection', 'sqli'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const injectionPayloads = [
				{ field: 'id', value: "1; DROP TABLE users;--" },
				{ field: 'query', value: "'; SELECT * FROM users;--" },
				{ field: 'name', value: "$(cat /etc/passwd)" },
				{ field: 'file', value: "../../etc/passwd" }
			];

			const responses: Array<{ payload: string; status: number; body: unknown }> = [];

			for (const payload of injectionPayloads) {
				try {
					const response = await fetch(`${ctx.targetUrl}/functions/v1/api`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ [payload.field]: payload.value })
					});

					const body = await response.text();

					// Check for signs of injection success
					if (
						body.includes('syntax error') ||
						body.includes('root:') ||
						body.includes('DROP TABLE') ||
						body.includes('SELECT *')
					) {
						responses.push({
							payload: `${payload.field}=${payload.value}`,
							status: response.status,
							body
						});
					}
				} catch {
					// Continue
				}
			}

			const breached = responses.length > 0;

			return {
				attackId: 'functions-injection',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Potential injection vulnerability detected'
					: 'No obvious injection vulnerabilities',
				details: {},
				evidence: breached ? { responses } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'functions-ssrf',
		name: 'Server-Side Request Forgery',
		description: 'Tests if functions can be tricked into making internal requests',
		category: 'functions',
		severity: 'high',
		tags: ['functions', 'ssrf', 'internal'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const ssrfPayloads = [
				'http://localhost:5432',
				'http://127.0.0.1:6379',
				'http://169.254.169.254/latest/meta-data/',
				'file:///etc/passwd'
			];

			const vulnerable: string[] = [];

			for (const payload of ssrfPayloads) {
				try {
					const response = await fetch(`${ctx.targetUrl}/functions/v1/api`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ url: payload, webhook: payload })
					});

					const body = await response.text();

					// Check for SSRF indicators
					if (
						body.includes('PostgreSQL') ||
						body.includes('redis') ||
						body.includes('ami-id') ||
						body.includes('root:x:')
					) {
						vulnerable.push(payload);
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'functions-ssrf',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'SSRF vulnerability detected - internal services may be accessible'
					: 'No SSRF vulnerabilities detected',
				details: {},
				evidence: breached ? { vulnerableUrls: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'functions-rate-limit',
		name: 'Missing Rate Limiting',
		description: 'Tests if functions have rate limiting enabled',
		category: 'functions',
		severity: 'medium',
		tags: ['functions', 'rate-limit', 'dos'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const requests = 50;
			let successCount = 0;

			for (let i = 0; i < requests; i++) {
				try {
					const response = await fetch(`${ctx.targetUrl}/functions/v1/api`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ test: i })
					});

					if (response.ok || response.status === 401) {
						successCount++;
					} else if (response.status === 429) {
						// Rate limited - good!
						break;
					}
				} catch {
					break;
				}
			}

			const breached = successCount >= requests;

			return {
				attackId: 'functions-rate-limit',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `No rate limiting - ${successCount}/${requests} requests succeeded`
					: `Rate limiting active - blocked after ${successCount} requests`,
				details: {},
				evidence: breached ? { requestsCompleted: successCount } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
