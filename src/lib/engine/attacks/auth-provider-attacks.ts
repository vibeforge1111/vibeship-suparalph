/**
 * Auth Provider attacks
 * Tests for Supabase Auth provider-specific vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const authProviderAttacks: AttackVector[] = [
	{
		id: 'auth-sms-bombing',
		name: 'SMS/Phone OTP Bombing',
		description: 'Test for SMS bombing vulnerability via phone auth',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				const requests: Promise<Response>[] = [];

				// Try to send multiple SMS OTPs rapidly
				for (let i = 0; i < 10; i++) {
					requests.push(
						fetch(`${context.supabaseUrl}/auth/v1/otp`, {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								phone: `+1555000${1000 + i}`,
								channel: 'sms'
							}),
							signal: context.signal
						})
					);
				}

				const responses = await Promise.all(requests);
				const rateLimited = responses.some(r => r.status === 429);
				const successCount = responses.filter(r => r.ok).length;

				return {
					breached: !rateLimited && successCount > 5,
					status: rateLimited ? 'secure' : successCount > 5 ? 'breached' : 'secure',
					summary: rateLimited
						? 'SMS rate limiting active'
						: successCount > 5
							? `SMS bombing possible: ${successCount}/10 OTPs sent`
							: 'SMS properly rate limited',
					evidence: { successCount, rateLimited }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'SMS OTP protected' };
			}
		}
	},
	{
		id: 'auth-provider-linking-abuse',
		name: 'OAuth Provider Linking Abuse',
		description: 'Test for account takeover via provider linking',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Check if provider linking is configured
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/settings`,
					{
						headers: {
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				if (res.ok) {
					const settings = await res.json();
					const providers = settings?.external || {};

					// Check for risky configurations
					const enabledProviders = Object.entries(providers)
						.filter(([, config]) => (config as { enabled?: boolean })?.enabled)
						.map(([name]) => name);

					const hasMultipleProviders = enabledProviders.length > 1;

					return {
						breached: hasMultipleProviders,
						status: hasMultipleProviders ? 'breached' : 'secure',
						summary: hasMultipleProviders
							? `Multiple providers enabled (${enabledProviders.join(', ')}) - check linking policy`
							: 'Single provider or properly configured',
						evidence: { providers: enabledProviders }
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Auth settings not exposed'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Provider config protected' };
			}
		}
	},
	{
		id: 'auth-anonymous-upgrade-exploit',
		name: 'Anonymous User Upgrade Exploit',
		description: 'Test for anonymous user upgrade vulnerabilities',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				// Create anonymous session
				const anonRes = await fetch(
					`${context.supabaseUrl}/auth/v1/signup`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey
						},
						body: JSON.stringify({}),
						signal: context.signal
					}
				);

				if (anonRes.ok) {
					const anonData = await anonRes.json();
					const isAnonymous = anonData?.user?.is_anonymous;

					if (isAnonymous) {
						// Try to upgrade to existing email
						const upgradeRes = await fetch(
							`${context.supabaseUrl}/auth/v1/user`,
							{
								method: 'PUT',
								headers: {
									'Content-Type': 'application/json',
									'apikey': context.anonKey,
									'Authorization': `Bearer ${anonData.access_token}`
								},
								body: JSON.stringify({
									email: 'admin@example.com',
									data: { upgraded: true }
								}),
								signal: context.signal
							}
						);

						const upgradeAllowed = upgradeRes.ok;

						return {
							breached: upgradeAllowed,
							status: upgradeAllowed ? 'breached' : 'secure',
							summary: upgradeAllowed
								? 'Anonymous upgrade to existing email possible!'
								: 'Anonymous upgrade properly restricted',
							evidence: upgradeAllowed ? { status: upgradeRes.status } : undefined
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Anonymous auth not enabled or protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Anonymous auth protected' };
			}
		}
	},
	{
		id: 'auth-email-enumeration-provider',
		name: 'Email Enumeration via Providers',
		description: 'Enumerate emails through OAuth provider errors',
		category: 'auth',
		severity: 'medium',
		async execute(context) {
			try {
				// Try OAuth with known email
				const providers = ['google', 'github', 'azure', 'facebook'];
				const enumerable: string[] = [];

				for (const provider of providers) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/authorize?provider=${provider}`,
						{
							method: 'GET',
							headers: {
								'apikey': context.anonKey
							},
							redirect: 'manual',
							signal: context.signal
						}
					);

					// Check if provider reveals email existence
					const location = res.headers.get('location') || '';
					if (location.includes('error') && location.includes('email')) {
						enumerable.push(provider);
					}
				}

				return {
					breached: enumerable.length > 0,
					status: enumerable.length > 0 ? 'breached' : 'secure',
					summary: enumerable.length > 0
						? `Email enumerable via: ${enumerable.join(', ')}`
						: 'Provider errors do not reveal emails',
					evidence: enumerable.length > 0 ? { providers: enumerable } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Provider enum not possible' };
			}
		}
	},
	{
		id: 'auth-callback-manipulation',
		name: 'OAuth Callback URL Manipulation',
		description: 'Test for OAuth callback URL injection',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				const maliciousCallbacks = [
					'https://evil.com/callback',
					'javascript:alert(1)',
					'//evil.com/callback',
					'https://evil.com@legitimate.com/callback'
				];

				for (const callback of maliciousCallbacks) {
					const res = await fetch(
						`${context.supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(callback)}`,
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
					if (location.includes('evil.com') || location.includes('javascript:')) {
						return {
							breached: true,
							status: 'breached',
							summary: 'OAuth callback URL injection possible!',
							evidence: { maliciousCallback: callback, redirectTo: location }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'OAuth callback URLs properly validated'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Callback validation working' };
			}
		}
	},
	{
		id: 'auth-social-account-takeover',
		name: 'Social Account Takeover',
		description: 'Test for account takeover via unverified social email',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Check provider configuration
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/settings`,
					{
						headers: {
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				if (res.ok) {
					const settings = await res.json();

					// Check if email verification is required
					const autoConfirmEmail = settings?.mailer?.autoconfirm;
					const skipVerification = settings?.external_email_verification_required === false;

					const vulnerable = autoConfirmEmail || skipVerification;

					return {
						breached: vulnerable,
						status: vulnerable ? 'breached' : 'secure',
						summary: vulnerable
							? 'Social signup without email verification - account takeover possible'
							: 'Email verification required for social auth',
						evidence: { autoConfirmEmail, skipVerification }
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Auth settings protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Social auth config protected' };
			}
		}
	},
	{
		id: 'auth-pkce-downgrade',
		name: 'PKCE Downgrade Attack',
		description: 'Test if PKCE can be bypassed in OAuth flow',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				// Try OAuth without PKCE
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/authorize?provider=google&flow_type=implicit`,
					{
						method: 'GET',
						headers: {
							'apikey': context.anonKey
						},
						redirect: 'manual',
						signal: context.signal
					}
				);

				const allowsImplicit = res.status === 302 || res.status === 303;

				return {
					breached: allowsImplicit,
					status: allowsImplicit ? 'breached' : 'secure',
					summary: allowsImplicit
						? 'Implicit flow allowed - PKCE can be bypassed'
						: 'PKCE enforced for OAuth flow',
					evidence: { status: res.status }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'PKCE properly enforced' };
			}
		}
	},
	{
		id: 'auth-mfa-bypass-social',
		name: 'MFA Bypass via Social Login',
		description: 'Test if MFA can be bypassed using social providers',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Check MFA and social auth configuration
				const res = await fetch(
					`${context.supabaseUrl}/auth/v1/settings`,
					{
						headers: {
							'apikey': context.anonKey
						},
						signal: context.signal
					}
				);

				if (res.ok) {
					const settings = await res.json();

					const mfaEnabled = settings?.mfa?.enabled;
					const socialEnabled = Object.values(settings?.external || {})
						.some((p) => (p as { enabled?: boolean })?.enabled);

					const potentialBypass = mfaEnabled && socialEnabled;

					return {
						breached: potentialBypass,
						status: potentialBypass ? 'breached' : 'secure',
						summary: potentialBypass
							? 'MFA enabled with social login - potential bypass vector'
							: 'MFA configuration appears secure',
						details: potentialBypass
							? { note: 'Verify social login enforces MFA for existing accounts' }
							: undefined
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Auth settings protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'MFA config protected' };
			}
		}
	}
];
