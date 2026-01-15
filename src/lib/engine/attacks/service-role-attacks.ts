/**
 * Service Role Key Detection Attacks
 * The #1 catastrophic Supabase vulnerability - exposed service_role keys bypass ALL RLS
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Service Role Key Detection Attacks
 */
export const serviceRoleAttacks: AttackVector[] = [
	{
		id: 'service-role-key-exposed',
		name: 'Service Role Key Exposure Detection',
		description: 'Checks if the service_role key is accidentally exposed or accessible',
		category: 'auth',
		severity: 'critical',
		tags: ['service-role', 'key-exposure', 'rls-bypass', 'critical'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Test 1: Check if anon key is actually a service_role key (common mistake)
			try {
				// Service role keys can access auth.users directly
				const authUsersRes = await fetch(`${ctx.targetUrl}/rest/v1/users?select=*&limit=1`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json'
					},
					signal: ctx.signal
				});

				// Also try the auth schema directly
				const authSchemaRes = await fetch(`${ctx.targetUrl}/rest/v1/auth.users?select=*&limit=1`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json'
					},
					signal: ctx.signal
				});

				if (authUsersRes.ok || authSchemaRes.ok) {
					const data = authUsersRes.ok ? await authUsersRes.json() : await authSchemaRes.json();
					if (Array.isArray(data) && data.length > 0) {
						findings.push('CRITICAL: Provided key can access auth.users - likely a service_role key!');
						breached = true;
					}
				}
			} catch {}

			// Test 2: Check for RLS bypass capability (service_role bypasses RLS)
			try {
				// Try to access with RLS bypass header (only works with service_role)
				const bypassRes = await fetch(`${ctx.targetUrl}/rest/v1/profiles?select=*&limit=100`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json',
						'X-Client-Info': 'supabase-js/2.0.0'
					},
					signal: ctx.signal
				});

				if (bypassRes.ok) {
					const data = await bypassRes.json();
					// If we get way more data than expected, might be service_role
					if (Array.isArray(data) && data.length > 50) {
						findings.push(`WARNING: Key returned ${data.length} rows - may have elevated privileges`);
					}
				}
			} catch {}

			// Test 3: Check JWT claims for role
			try {
				const parts = ctx.anonKey.split('.');
				if (parts.length === 3) {
					const payload = JSON.parse(atob(parts[1]));
					if (payload.role === 'service_role') {
						findings.push('CRITICAL: JWT role is "service_role" - this key bypasses ALL RLS!');
						breached = true;
					} else if (payload.role === 'authenticated' && !payload.sub) {
						findings.push('WARNING: Authenticated role without user ID - suspicious key');
					}
				}
			} catch {}

			return {
				attackId: 'service-role-key-exposed',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: breached
					? 'CRITICAL: Service role key detected - bypasses all RLS!'
					: findings.length > 0
						? `Found ${findings.length} potential key exposure issues`
						: 'No service role key exposure detected',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	},

	{
		id: 'service-role-in-client-bundle',
		name: 'Service Role Key in Client Bundle',
		description: 'Detects if service_role key patterns exist in client-accessible responses',
		category: 'auth',
		severity: 'critical',
		tags: ['service-role', 'client-exposure', 'javascript', 'critical'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Common endpoints that might leak keys
			const endpointsToCheck = [
				'/',
				'/config',
				'/api/config',
				'/_next/static',
				'/static/js',
				'/assets',
				'/env',
				'/.env',
				'/config.js',
				'/supabase.js'
			];

			// Service role key patterns (they have specific JWT structure)
			const serviceRolePatterns = [
				/service_role/i,
				/eyJ[A-Za-z0-9_-]+\.eyJ[^"'`\s]+role["'\s]*:["'\s]*service_role/,
				/SUPABASE_SERVICE_ROLE/i,
				/SERVICE_ROLE_KEY/i,
				/serviceRoleKey/i
			];

			// Extract base URL (remove /rest/v1 etc)
			const baseUrl = ctx.targetUrl.replace(/\/rest\/v1\/?$/, '');

			for (const endpoint of endpointsToCheck) {
				try {
					const res = await fetch(`${baseUrl}${endpoint}`, {
						headers: { 'Accept': 'text/html,application/json,*/*' },
						signal: ctx.signal
					});

					if (res.ok) {
						const text = await res.text();
						for (const pattern of serviceRolePatterns) {
							if (pattern.test(text)) {
								findings.push(`Service role key pattern found at ${endpoint}`);
								breached = true;
								break;
							}
						}
					}
				} catch {}
			}

			return {
				attackId: 'service-role-in-client-bundle',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: Service role key exposed in ${findings.length} location(s)!`
					: 'No service role key found in client-accessible endpoints',
				details: { findings, checkedEndpoints: endpointsToCheck.length },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'service-role-rls-bypass-test',
		name: 'RLS Bypass via Elevated Key',
		description: 'Tests if the provided key can bypass RLS restrictions entirely',
		category: 'rls',
		severity: 'critical',
		tags: ['service-role', 'rls-bypass', 'privilege-escalation'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const bypassedTables: string[] = [];
			let breached = false;

			// Tables that should ALWAYS be protected
			const protectedTables = [
				'users',
				'profiles',
				'accounts',
				'auth.users',
				'secrets',
				'api_keys',
				'tokens',
				'sessions',
				'credentials',
				'passwords',
				'private_data',
				'admin_settings',
				'billing',
				'payments',
				'subscriptions'
			];

			for (const table of protectedTables) {
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=5`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 0) {
							bypassedTables.push(`${table} (${data.length} rows exposed)`);
							breached = true;
						}
					}
				} catch {}
			}

			return {
				attackId: 'service-role-rls-bypass-test',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `RLS bypassed on ${bypassedTables.length} protected tables!`
					: 'RLS appears to be enforced on protected tables',
				details: { bypassedTables },
				evidence: breached ? { bypassedTables } : undefined
			};
		}
	},

	{
		id: 'service-role-admin-operations',
		name: 'Admin Operations Accessible',
		description: 'Tests if admin-level database operations are accessible with current key',
		category: 'database',
		severity: 'critical',
		tags: ['service-role', 'admin', 'database', 'privilege-escalation'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Test 1: Can we call RPC functions that should be admin-only?
			const adminFunctions = [
				'pg_stat_statements',
				'pg_stat_activity',
				'get_all_users',
				'admin_get_users',
				'get_service_role',
				'execute_sql',
				'run_query'
			];

			for (const func of adminFunctions) {
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${func}`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({}),
						signal: ctx.signal
					});

					if (res.ok) {
						findings.push(`Admin function accessible: ${func}`);
						breached = true;
					}
				} catch {}
			}

			// Test 2: Can we access pg_catalog?
			try {
				const res = await fetch(`${ctx.targetUrl}/rest/v1/pg_catalog.pg_tables?select=*&limit=5`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json'
					},
					signal: ctx.signal
				});

				if (res.ok) {
					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						findings.push('Can access pg_catalog - elevated privileges detected');
						breached = true;
					}
				}
			} catch {}

			// Test 3: Can we query information_schema?
			try {
				const res = await fetch(`${ctx.targetUrl}/rest/v1/information_schema.tables?select=*&limit=10`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json'
					},
					signal: ctx.signal
				});

				if (res.ok) {
					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						findings.push(`Can query information_schema - found ${data.length} tables`);
						breached = true;
					}
				}
			} catch {}

			return {
				attackId: 'service-role-admin-operations',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: ${findings.length} admin operations accessible!`
					: 'Admin operations properly restricted',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'service-role-storage-bypass',
		name: 'Storage RLS Bypass Detection',
		description: 'Tests if storage bucket policies can be bypassed with current key',
		category: 'storage',
		severity: 'critical',
		tags: ['service-role', 'storage', 'rls-bypass'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const accessibleBuckets: string[] = [];
			let breached = false;

			// Common bucket names that should be protected
			const protectedBuckets = [
				'private',
				'avatars',
				'documents',
				'uploads',
				'files',
				'media',
				'attachments',
				'user-data',
				'internal',
				'admin'
			];

			const storageUrl = ctx.targetUrl.replace('/rest/v1', '/storage/v1');

			for (const bucket of protectedBuckets) {
				try {
					// Try to list bucket contents
					const res = await fetch(`${storageUrl}/object/list/${bucket}`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ prefix: '', limit: 10 }),
						signal: ctx.signal
					});

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 0) {
							accessibleBuckets.push(`${bucket} (${data.length} files visible)`);
							breached = true;
						}
					}
				} catch {}
			}

			return {
				attackId: 'service-role-storage-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Storage bypass on ${accessibleBuckets.length} protected buckets!`
					: 'Storage bucket policies appear enforced',
				details: { accessibleBuckets },
				evidence: breached ? { accessibleBuckets } : undefined
			};
		}
	},

	{
		id: 'service-role-jwt-analysis',
		name: 'JWT Token Role Analysis',
		description: 'Analyzes JWT token to detect privilege level and potential misuse',
		category: 'auth',
		severity: 'high',
		tags: ['jwt', 'role', 'analysis', 'service-role'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			try {
				const parts = ctx.anonKey.split('.');
				if (parts.length !== 3) {
					return {
						attackId: 'service-role-jwt-analysis',
						status: 'error',
						breached: false,
						summary: 'Invalid JWT format'
					};
				}

				const header = JSON.parse(atob(parts[0]));
				const payload = JSON.parse(atob(parts[1]));

				// Check role
				if (payload.role === 'service_role') {
					findings.push('CRITICAL: Token has service_role - bypasses all RLS!');
					breached = true;
				} else if (payload.role === 'supabase_admin') {
					findings.push('CRITICAL: Token has supabase_admin role!');
					breached = true;
				} else if (payload.role === 'postgres') {
					findings.push('CRITICAL: Token has postgres superuser role!');
					breached = true;
				}

				// Check for suspicious claims
				if (payload.is_super_admin) {
					findings.push('Token has is_super_admin claim');
					breached = true;
				}

				if (payload.aal === 'aal2' && !payload.amr) {
					findings.push('WARNING: AAL2 without AMR - suspicious token');
				}

				// Check expiration
				if (payload.exp) {
					const expDate = new Date(payload.exp * 1000);
					const now = new Date();
					const daysUntilExpiry = (expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

					if (daysUntilExpiry > 365) {
						findings.push(`WARNING: Token expires in ${Math.round(daysUntilExpiry)} days - unusually long`);
					}
				}

				// Check issuer
				if (!payload.iss || !payload.iss.includes('supabase')) {
					findings.push('WARNING: Unusual token issuer');
				}

				return {
					attackId: 'service-role-jwt-analysis',
					status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
					breached: breached || findings.length > 0,
					summary: breached
						? 'CRITICAL: Elevated privilege token detected!'
						: findings.length > 0
							? `Found ${findings.length} JWT concerns`
							: 'JWT appears to be standard anon key',
					details: {
						role: payload.role,
						issuer: payload.iss,
						findings
					},
					evidence: { role: payload.role, findings }
				};
			} catch (e) {
				return {
					attackId: 'service-role-jwt-analysis',
					status: 'error',
					breached: false,
					summary: 'Could not parse JWT token'
				};
			}
		}
	}
];
