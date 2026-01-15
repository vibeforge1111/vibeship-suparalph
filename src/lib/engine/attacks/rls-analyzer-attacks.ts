/**
 * RLS Policy Analyzer Attacks
 * Deep analysis of RLS policies to detect vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Dangerous RLS patterns to detect
 */
const DANGEROUS_PATTERNS = [
	{ pattern: /USING\s*\(\s*true\s*\)/i, name: 'USING(true)', severity: 'critical', description: 'Allows all access' },
	{ pattern: /WITH\s+CHECK\s*\(\s*true\s*\)/i, name: 'WITH CHECK(true)', severity: 'critical', description: 'Allows all writes' },
	{ pattern: /USING\s*\(\s*1\s*=\s*1\s*\)/i, name: 'USING(1=1)', severity: 'critical', description: 'Always true condition' },
	{ pattern: /USING\s*\(\s*'[^']*'\s*=\s*'[^']*'\s*\)/i, name: "USING('a'='a')", severity: 'critical', description: 'String comparison always true' },
	{ pattern: /FOR\s+ALL/i, name: 'FOR ALL', severity: 'high', description: 'Single policy for all operations' },
	{ pattern: /TO\s+public/i, name: 'TO public', severity: 'high', description: 'Policy grants access to public role' },
	{ pattern: /TO\s+anon/i, name: 'TO anon', severity: 'medium', description: 'Policy grants access to anonymous users' },
];

/**
 * Safe patterns that should be present
 */
const SAFE_PATTERNS = [
	{ pattern: /auth\.uid\(\)/i, name: 'auth.uid()', description: 'User ID check' },
	{ pattern: /auth\.jwt\(\)/i, name: 'auth.jwt()', description: 'JWT claim check' },
	{ pattern: /current_user/i, name: 'current_user', description: 'Current user check' },
	{ pattern: /session_user/i, name: 'session_user', description: 'Session user check' },
];

export const rlsAnalyzerAttacks: AttackVector[] = [
	{
		id: 'rls-policy-fetch-analyze',
		name: 'RLS Policy Deep Analysis',
		description: 'Fetches and analyzes RLS policies for dangerous patterns',
		category: 'rls',
		severity: 'high',
		tags: ['rls', 'policy', 'analysis', 'security-audit'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: Array<{ table: string; policy: string; issues: string[] }> = [];
			let breached = false;

			// Try to fetch policies via RPC (if exposed)
			try {
				const policyRes = await fetch(`${ctx.targetUrl}/rest/v1/rpc/get_policies`, {
					method: 'POST',
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`,
						'Content-Type': 'application/json'
					},
					body: JSON.stringify({}),
					signal: ctx.signal
				});

				if (policyRes.ok) {
					const policies = await policyRes.json();
					// Analyze each policy
					if (Array.isArray(policies)) {
						for (const policy of policies) {
							const issues: string[] = [];
							const policyText = JSON.stringify(policy);

							for (const { pattern, name, severity, description } of DANGEROUS_PATTERNS) {
								if (pattern.test(policyText)) {
									issues.push(`[${severity.toUpperCase()}] ${name}: ${description}`);
									if (severity === 'critical') breached = true;
								}
							}

							// Check for missing safe patterns
							const hasSafePattern = SAFE_PATTERNS.some(p => p.pattern.test(policyText));
							if (!hasSafePattern && policyText.includes('USING')) {
								issues.push('[WARNING] No auth.uid() or similar check found');
							}

							if (issues.length > 0) {
								findings.push({
									table: policy.tablename || 'unknown',
									policy: policy.policyname || 'unknown',
									issues
								});
							}
						}
					}
				}
			} catch {}

			// Try alternative: query pg_policies directly
			if (findings.length === 0) {
				try {
					const pgPoliciesRes = await fetch(`${ctx.targetUrl}/rest/v1/pg_policies?select=*`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (pgPoliciesRes.ok) {
						const policies = await pgPoliciesRes.json();
						findings.push({
							table: 'pg_policies',
							policy: 'direct_access',
							issues: [`Found ${policies.length} policies accessible - review manually`]
						});
						breached = true;
					}
				} catch {}
			}

			return {
				attackId: 'rls-policy-fetch-analyze',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: breached
					? `Found ${findings.length} tables with dangerous RLS policies!`
					: 'Could not fetch RLS policies (this is expected if properly secured)',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	},

	{
		id: 'rls-missing-policy-detection',
		name: 'Tables Without RLS Policies',
		description: 'Identifies tables that have RLS enabled but no policies defined',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'missing-policy', 'security-gap'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const tablesWithoutPolicies: string[] = [];
			let breached = false;

			// Discover tables via OpenAPI
			let discoveredTables: string[] = [];
			try {
				const schemaRes = await fetch(`${ctx.targetUrl}/rest/v1/`, {
					headers: {
						'apikey': ctx.anonKey,
						'Authorization': `Bearer ${ctx.anonKey}`
					},
					signal: ctx.signal
				});

				if (schemaRes.ok) {
					const schema = await schemaRes.json();
					if (schema.paths) {
						discoveredTables = Object.keys(schema.paths)
							.filter(p => p.startsWith('/') && !p.includes('{'))
							.map(p => p.slice(1));
					}
				}
			} catch {}

			// Test each table - if we can access it, either RLS is off or policy is too permissive
			for (const table of discoveredTables) {
				try {
					// Try to SELECT without auth
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data)) {
							// Even empty array means table is accessible
							tablesWithoutPolicies.push(table);
							if (data.length > 0) {
								breached = true;
							}
						}
					}
				} catch {}
			}

			return {
				attackId: 'rls-missing-policy-detection',
				status: breached ? 'breached' : tablesWithoutPolicies.length > 0 ? 'breached' : 'secure',
				breached: breached || tablesWithoutPolicies.length > 0,
				summary: tablesWithoutPolicies.length > 0
					? `${tablesWithoutPolicies.length} tables accessible (missing or weak RLS)!`
					: 'All discovered tables appear properly restricted',
				details: {
					accessibleTables: tablesWithoutPolicies,
					totalTablesChecked: discoveredTables.length
				},
				evidence: tablesWithoutPolicies.length > 0 ? { tablesWithoutPolicies } : undefined
			};
		}
	},

	{
		id: 'rls-operation-coverage-test',
		name: 'RLS Operation Coverage Test',
		description: 'Tests if all CRUD operations are covered by RLS policies',
		category: 'rls',
		severity: 'high',
		tags: ['rls', 'crud', 'coverage', 'security-audit'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: Array<{ table: string; vulnerableOperations: string[] }> = [];
			let breached = false;

			// Common tables to test
			const tablesToTest = ['users', 'profiles', 'accounts', 'posts', 'comments', 'orders', 'items'];

			for (const table of tablesToTest) {
				const vulnerableOps: string[] = [];

				// Test SELECT
				try {
					const selectRes = await fetch(`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});
					if (selectRes.ok) {
						const data = await selectRes.json();
						if (Array.isArray(data) && data.length > 0) {
							vulnerableOps.push('SELECT');
							breached = true;
						}
					}
				} catch {}

				// Test INSERT (with dummy data that should fail)
				try {
					const insertRes = await fetch(`${ctx.targetUrl}/rest/v1/${table}`, {
						method: 'POST',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							'Prefer': 'return=minimal'
						},
						body: JSON.stringify({ test_field: 'rls_test_' + Date.now() }),
						signal: ctx.signal
					});
					// 201 = inserted, 409 = conflict (but INSERT was attempted)
					if (insertRes.status === 201 || insertRes.status === 409) {
						vulnerableOps.push('INSERT');
						breached = true;
					}
				} catch {}

				// Test UPDATE (should fail without proper auth)
				try {
					const updateRes = await fetch(`${ctx.targetUrl}/rest/v1/${table}?id=eq.99999`, {
						method: 'PATCH',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json',
							'Prefer': 'return=minimal'
						},
						body: JSON.stringify({ updated_at: new Date().toISOString() }),
						signal: ctx.signal
					});
					if (updateRes.ok || updateRes.status === 204) {
						vulnerableOps.push('UPDATE');
						breached = true;
					}
				} catch {}

				// Test DELETE (should fail without proper auth)
				try {
					const deleteRes = await fetch(`${ctx.targetUrl}/rest/v1/${table}?id=eq.99999`, {
						method: 'DELETE',
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Prefer': 'return=minimal'
						},
						signal: ctx.signal
					});
					if (deleteRes.ok || deleteRes.status === 204) {
						vulnerableOps.push('DELETE');
						breached = true;
					}
				} catch {}

				if (vulnerableOps.length > 0) {
					findings.push({ table, vulnerableOperations: vulnerableOps });
				}
			}

			return {
				attackId: 'rls-operation-coverage-test',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${findings.length} tables have incomplete RLS coverage!`
					: 'All tested tables have complete operation coverage',
				details: { findings },
				evidence: breached ? { findings } : undefined
			};
		}
	},

	{
		id: 'rls-policy-bypass-techniques',
		name: 'RLS Policy Bypass Techniques',
		description: 'Tests various techniques to bypass RLS policies',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'bypass', 'exploit', 'security-test'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const bypasses: Array<{ technique: string; table: string; result: string }> = [];
			let breached = false;

			const tables = ['users', 'profiles', 'accounts', 'data'];

			for (const table of tables) {
				// Technique 1: OR 1=1 injection in filters
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?or=(id.eq.1,id.neq.1)&select=*&limit=5`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});
					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 1) {
							bypasses.push({ technique: 'OR condition bypass', table, result: `${data.length} rows` });
							breached = true;
						}
					}
				} catch {}

				// Technique 2: Negation bypass
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?id=not.is.null&select=*&limit=5`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});
					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 1) {
							bypasses.push({ technique: 'NOT NULL bypass', table, result: `${data.length} rows` });
							breached = true;
						}
					}
				} catch {}

				// Technique 3: Range query bypass
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?id=gte.0&select=*&limit=5`, {
						headers: {
							'apikey': ctx.anonKey,
							'Authorization': `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						signal: ctx.signal
					});
					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 1) {
							bypasses.push({ technique: 'Range query bypass', table, result: `${data.length} rows` });
							breached = true;
						}
					}
				} catch {}

				// Technique 4: JSON column access
				try {
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?select=*,metadata->*&limit=5`, {
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
							const hasMetadata = data.some(d => d.metadata);
							if (hasMetadata) {
								bypasses.push({ technique: 'JSON column access', table, result: 'metadata exposed' });
								breached = true;
							}
						}
					}
				} catch {}
			}

			return {
				attackId: 'rls-policy-bypass-techniques',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${bypasses.length} RLS bypass techniques succeeded!`
					: 'No RLS bypass techniques succeeded',
				details: { bypasses },
				evidence: breached ? { bypasses } : undefined
			};
		}
	},

	{
		id: 'rls-cross-user-access',
		name: 'Cross-User Data Access Test',
		description: 'Tests if one user can access another users data',
		category: 'rls',
		severity: 'critical',
		tags: ['rls', 'cross-user', 'horizontal-escalation'],
		async execute(ctx: AttackContext): Promise<AttackResult> {
			const findings: string[] = [];
			let breached = false;

			// Tables likely to have user-owned data
			const userTables = ['profiles', 'user_data', 'settings', 'preferences', 'documents'];

			for (const table of userTables) {
				try {
					// First, see if we can get any data
					const res = await fetch(`${ctx.targetUrl}/rest/v1/${table}?select=*,user_id&limit=10`, {
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
							// Check if we got data from multiple users
							const userIds = new Set(data.map((d: Record<string, unknown>) => d.user_id).filter(Boolean));
							if (userIds.size > 1) {
								findings.push(`${table}: Can access data from ${userIds.size} different users!`);
								breached = true;
							} else if (data.length > 0) {
								findings.push(`${table}: Can access user data (single user visible)`);
							}
						}
					}
				} catch {}
			}

			return {
				attackId: 'rls-cross-user-access',
				status: breached ? 'breached' : findings.length > 0 ? 'breached' : 'secure',
				breached: breached || findings.length > 0,
				summary: breached
					? `CRITICAL: Cross-user data access possible on ${findings.length} tables!`
					: findings.length > 0
						? `${findings.length} tables with potential access issues`
						: 'No cross-user data access detected',
				details: { findings },
				evidence: findings.length > 0 ? { findings } : undefined
			};
		}
	}
];
