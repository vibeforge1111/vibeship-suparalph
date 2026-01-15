/**
 * Management API attacks
 * Tests for Supabase management/admin API vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const managementApiAttacks: AttackVector[] = [
	{
		id: 'mgmt-api-exposure',
		name: 'Management API Exposure',
		description: 'Check if management API endpoints are accessible',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				const mgmtEndpoints = [
					'/rest/v1/rpc/get_service_role_config',
					'/admin/v1/projects',
					'/admin/v1/settings',
					'/v1/projects',
					'/management/v1/organizations'
				];

				const accessible: string[] = [];

				for (const endpoint of mgmtEndpoints) {
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

					if (res.ok || (res.status !== 404 && res.status !== 403)) {
						accessible.push(endpoint);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Management endpoints exposed: ${accessible.join(', ')}`
						: 'Management API properly protected',
					evidence: accessible.length > 0 ? { endpoints: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Management API not accessible' };
			}
		}
	},
	{
		id: 'mgmt-project-settings',
		name: 'Project Settings Exposure',
		description: 'Check if project settings are readable',
		category: 'auth',
		severity: 'high',
		async execute(context) {
			try {
				const settingsEndpoints = [
					'/rest/v1/project_settings?select=*',
					'/rest/v1/settings?select=*',
					'/rest/v1/configurations?select=*'
				];

				for (const endpoint of settingsEndpoints) {
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

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						return {
							breached: true,
							status: 'breached',
							summary: `Project settings exposed via ${endpoint}`,
							evidence: { endpoint, sampleData: data[0] }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Project settings not exposed'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Settings endpoints not accessible' };
			}
		}
	},
	{
		id: 'mgmt-service-key-check',
		name: 'Service Key Detection',
		description: 'Check if service role key might be exposed',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Check if anon key has elevated permissions
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/auth.users?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();

				// If we can access auth.users, the key might be service role
				const hasServiceAccess = Array.isArray(data) && data.length > 0;

				return {
					breached: hasServiceAccess,
					status: hasServiceAccess ? 'breached' : 'secure',
					summary: hasServiceAccess
						? 'CRITICAL: Key has service role access to auth.users!'
						: 'Key has appropriate anon permissions',
					evidence: hasServiceAccess ? { userCount: data.length } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'auth.users not accessible' };
			}
		}
	},
	{
		id: 'mgmt-migration-access',
		name: 'Migration History Access',
		description: 'Check if database migration history is accessible',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				const migrationTables = [
					'supabase_migrations.schema_migrations',
					'schema_migrations',
					'_migrations',
					'migrations'
				];

				for (const table of migrationTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*`,
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
						return {
							breached: true,
							status: 'breached',
							summary: `Migration history exposed: ${data.length} migrations visible`,
							evidence: { table, migrationCount: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Migration history protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Migration tables not accessible' };
			}
		}
	},
	{
		id: 'mgmt-edge-function-list',
		name: 'Edge Function Enumeration',
		description: 'Enumerate deployed edge functions',
		category: 'functions',
		severity: 'medium',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/functions/v1/`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();

				if (data?.functions || Array.isArray(data)) {
					const functions = data.functions || data;
					return {
						breached: true,
						status: 'breached',
						summary: `Edge functions enumerable: ${functions.length || 'unknown'} functions`,
						evidence: { functions: functions.slice?.(0, 5) }
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Edge function listing protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Function listing not accessible' };
			}
		}
	},
	{
		id: 'mgmt-database-roles',
		name: 'Database Role Enumeration',
		description: 'Check if database roles can be enumerated',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const roleQueries = [
					'pg_roles?select=rolname,rolsuper,rolcreaterole',
					'pg_catalog.pg_roles?select=*',
					'information_schema.role_table_grants?select=*'
				];

				for (const query of roleQueries) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${query}`,
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
						return {
							breached: true,
							status: 'breached',
							summary: `Database roles exposed: ${data.length} roles visible`,
							evidence: {
								roles: data.slice(0, 5).map((r: { rolname: string }) => r.rolname)
							}
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Database roles protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Role enumeration blocked' };
			}
		}
	},
	{
		id: 'mgmt-extension-list',
		name: 'Extension Enumeration',
		description: 'List installed PostgreSQL extensions',
		category: 'rls',
		severity: 'low',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/pg_extension?select=extname,extversion`,
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
					return {
						breached: true,
						status: 'breached',
						summary: `${data.length} extensions enumerable`,
						evidence: {
							extensions: data.map((e: { extname: string }) => e.extname)
						}
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Extension list protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Extensions not enumerable' };
			}
		}
	},
	{
		id: 'mgmt-api-version-info',
		name: 'API Version Information Disclosure',
		description: 'Check for version information leakage',
		category: 'rls',
		severity: 'low',
		async execute(context) {
			try {
				const endpoints = [
					'/rest/v1/',
					'/auth/v1/',
					'/storage/v1/',
					'/realtime/v1/',
					'/graphql/v1'
				];

				const versionInfo: Array<{ endpoint: string; version: string | null; server: string | null }> = [];

				for (const endpoint of endpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							method: 'OPTIONS',
							headers: {
								'apikey': context.anonKey
							},
							signal: context.signal
						}
					);

					const server = res.headers.get('server');
					const version = res.headers.get('x-version') ||
						res.headers.get('x-api-version') ||
						res.headers.get('x-postgrest-version');

					if (server || version) {
						versionInfo.push({ endpoint, version, server });
					}
				}

				return {
					breached: versionInfo.length > 0,
					status: versionInfo.length > 0 ? 'breached' : 'secure',
					summary: versionInfo.length > 0
						? `Version info exposed for ${versionInfo.length} endpoints`
						: 'Version information hidden',
					evidence: versionInfo.length > 0 ? { versions: versionInfo } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Version info not exposed' };
			}
		}
	},
	{
		id: 'mgmt-branch-access',
		name: 'Database Branch Access',
		description: 'Check for access to database branches',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Check for branch-related tables
				const branchTables = [
					'supabase_branches',
					'branches',
					'database_branches',
					'preview_branches'
				];

				for (const table of branchTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*`,
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
						return {
							breached: true,
							status: 'breached',
							summary: `Branch information exposed via ${table}`,
							evidence: { table, branchCount: data.length }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Branch information protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Branch tables not accessible' };
			}
		}
	}
];
