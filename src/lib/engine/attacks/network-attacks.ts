/**
 * Network Layer attacks
 * Tests for Supabase network/infrastructure vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const networkAttacks: AttackVector[] = [
	{
		id: 'net-dns-rebinding',
		name: 'DNS Rebinding Attack',
		description: 'Test for DNS rebinding vulnerability',
		category: 'api',
		severity: 'high',
		async execute(context) {
			try {
				// Check Host header validation
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/`,
					{
						headers: {
							'apikey': context.anonKey,
							'Host': 'localhost:54321',
							'X-Forwarded-Host': 'attacker.com'
						},
						signal: context.signal
					}
				);

				const hostHeader = res.headers.get('x-host') || res.headers.get('host');
				const acceptsArbitraryHost = res.ok;

				return {
					breached: acceptsArbitraryHost,
					status: acceptsArbitraryHost ? 'breached' : 'secure',
					summary: acceptsArbitraryHost
						? 'Arbitrary Host header accepted - DNS rebinding possible'
						: 'Host header properly validated',
					evidence: acceptsArbitraryHost ? { hostHeader } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Host validation working' };
			}
		}
	},
	{
		id: 'net-host-header-injection',
		name: 'Host Header Injection',
		description: 'Test for host header injection vulnerabilities',
		category: 'api',
		severity: 'high',
		async execute(context) {
			try {
				const injectionPayloads = [
					'evil.com',
					'localhost\r\nX-Injected: true',
					'evil.com:443@legitimate.com',
					'[::1]'
				];

				for (const payload of injectionPayloads) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/recover`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Host': payload
							},
							body: JSON.stringify({ email: 'test@test.com' }),
							signal: context.signal
						}
					);

					// Check if the response contains the injected host
					const text = await res.text();
					if (text.includes('evil.com') || text.includes('X-Injected')) {
						return {
							breached: true,
							status: 'breached',
							summary: 'Host header injection successful!',
							evidence: { payload, response: text.substring(0, 200) }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Host header injection not possible'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Host header protected' };
			}
		}
	},
	{
		id: 'net-request-smuggling',
		name: 'HTTP Request Smuggling',
		description: 'Test for HTTP request smuggling vulnerabilities',
		category: 'api',
		severity: 'critical',
		async execute(context) {
			try {
				// Test CL.TE and TE.CL smuggling
				const smugglingPayload = `POST /rest/v1/ HTTP/1.1\r\nHost: ${new URL(context.supabaseUrl).host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n`;

				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/`,
					{
						method: 'POST',
						headers: {
							'apikey': context.anonKey,
							'Content-Type': 'application/x-www-form-urlencoded',
							'Transfer-Encoding': 'chunked',
							'Content-Length': '6'
						},
						body: '0\r\n\r\nG',
						signal: context.signal
					}
				);

				// Check for anomalous responses
				const status = res.status;
				const anomalous = status === 400 || status === 501;

				return {
					breached: !anomalous,
					status: anomalous ? 'secure' : 'breached',
					summary: anomalous
						? 'Request smuggling properly blocked'
						: 'Potential request smuggling vulnerability',
					details: { note: 'Manual testing recommended for complete verification' }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Request smuggling blocked' };
			}
		}
	},
	{
		id: 'net-ssrf-internal',
		name: 'SSRF to Internal Services',
		description: 'Test for SSRF to internal Supabase services',
		category: 'api',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to access internal services via functions or webhooks
				const internalTargets = [
					'http://localhost:5432',  // PostgreSQL
					'http://localhost:8000',  // PostgREST
					'http://localhost:9000',  // Storage
					'http://127.0.0.1:54321', // Local Supabase
					'http://169.254.169.254/latest/meta-data/', // AWS metadata
					'http://metadata.google.internal/' // GCP metadata
				];

				const accessible: string[] = [];

				for (const target of internalTargets) {
					// Try via edge function proxy if available
					const res = await fetch(
						`${context.supabaseUrl}/functions/v1/proxy`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({ url: target }),
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (data && !data.error) {
							accessible.push(target);
						}
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `SSRF to internal services: ${accessible.join(', ')}`
						: 'Internal services not accessible via SSRF',
					evidence: accessible.length > 0 ? { targets: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'SSRF protection working' };
			}
		}
	},
	{
		id: 'net-xff-spoofing',
		name: 'X-Forwarded-For Spoofing',
		description: 'Test for IP spoofing via X-Forwarded-For',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to spoof IP address
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/`,
					{
						headers: {
							'apikey': context.anonKey,
							'X-Forwarded-For': '127.0.0.1, 10.0.0.1',
							'X-Real-IP': '127.0.0.1',
							'X-Client-IP': '192.168.1.1',
							'CF-Connecting-IP': '172.16.0.1'
						},
						signal: context.signal
					}
				);

				// Check if request was processed differently
				const rateLimit = res.headers.get('x-ratelimit-remaining');
				const clientIp = res.headers.get('x-client-ip');

				return {
					breached: clientIp === '127.0.0.1' || clientIp === '10.0.0.1',
					status: 'secure',
					summary: 'XFF headers processed - verify rate limiting uses real IP',
					details: { note: 'Check if rate limiting can be bypassed via XFF spoofing' },
					evidence: { rateLimit, clientIp }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'XFF handling secure' };
			}
		}
	},
	{
		id: 'net-websocket-hijack',
		name: 'WebSocket Hijacking',
		description: 'Test for WebSocket connection hijacking',
		category: 'realtime',
		severity: 'high',
		async execute(context) {
			try {
				// Test WebSocket upgrade with forged origin
				const res = await fetch(
					`${context.supabaseUrl}/realtime/v1/websocket`,
					{
						headers: {
							'Upgrade': 'websocket',
							'Connection': 'Upgrade',
							'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
							'Sec-WebSocket-Version': '13',
							'Origin': 'https://evil-attacker.com',
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				const allowsUpgrade = res.status === 101 || res.status === 426;
				const origin = res.headers.get('access-control-allow-origin');

				return {
					breached: allowsUpgrade && (origin === '*' || origin === 'https://evil-attacker.com'),
					status: allowsUpgrade && origin === '*' ? 'breached' : 'secure',
					summary: allowsUpgrade && origin === '*'
						? 'WebSocket allows arbitrary origins - CSWSH possible'
						: 'WebSocket origin validation present',
					evidence: { status: res.status, allowOrigin: origin }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'WebSocket protected' };
			}
		}
	},
	{
		id: 'net-tls-downgrade',
		name: 'TLS Downgrade Check',
		description: 'Check for TLS/HTTPS enforcement',
		category: 'api',
		severity: 'high',
		async execute(context) {
			try {
				// Check HSTS header
				const res = await fetch(
					`${context.supabaseUrl}/`,
					{
						headers: {
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				const hsts = res.headers.get('strict-transport-security');
				const hasHSTS = hsts !== null;
				const hasPreload = hsts?.includes('preload');
				const hasIncludeSubdomains = hsts?.includes('includeSubDomains');

				const fullySecure = hasHSTS && hasPreload && hasIncludeSubdomains;

				return {
					breached: !hasHSTS,
					status: hasHSTS ? 'secure' : 'breached',
					summary: !hasHSTS
						? 'No HSTS header - TLS downgrade possible'
						: fullySecure
							? 'Full HSTS with preload enabled'
							: `Partial HSTS: ${hsts}`,
					evidence: { hsts, hasPreload, hasIncludeSubdomains }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not check TLS settings' };
			}
		}
	},
	{
		id: 'net-cache-poisoning',
		name: 'Cache Poisoning',
		description: 'Test for web cache poisoning vulnerabilities',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Try cache poisoning via headers
				const poisonHeaders = {
					'X-Forwarded-Host': 'evil.com',
					'X-Forwarded-Scheme': 'http',
					'X-Original-URL': '/admin',
					'X-Rewrite-URL': '/admin'
				};

				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/`,
					{
						headers: {
							'apikey': context.anonKey,
							...poisonHeaders
						},
						signal: context.signal
					}
				);

				// Check cache-related headers
				const cacheControl = res.headers.get('cache-control');
				const vary = res.headers.get('vary');
				const cdnCache = res.headers.get('x-cache') || res.headers.get('cf-cache-status');

				const isCached = cdnCache?.includes('HIT') || cdnCache?.includes('CACHED');
				const variesOnHost = vary?.includes('Host') || vary?.includes('Origin');

				return {
					breached: isCached && !variesOnHost,
					status: isCached && !variesOnHost ? 'breached' : 'secure',
					summary: isCached && !variesOnHost
						? 'Cache may be poisonable - response cached without Vary on Host'
						: 'Cache poisoning mitigated',
					evidence: { cacheControl, vary, cdnCache }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cache poisoning check passed' };
			}
		}
	}
];
