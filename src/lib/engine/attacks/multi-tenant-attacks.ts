/**
 * Multi-tenancy attacks
 * Tests for tenant isolation bypass vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const multiTenantAttacks: AttackVector[] = [
	{
		id: 'tenant-id-manipulation',
		name: 'Tenant ID Manipulation',
		description: 'Attempt to access other tenants data by manipulating tenant_id',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			const accessibleTables: string[] = [];

			try {
				// Get list of tables first
				const schemaRes = await fetch(
					`${context.supabaseUrl}/rest/v1/`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				// Try common tenant ID patterns
				const tenantIds = [
					'00000000-0000-0000-0000-000000000000',
					'11111111-1111-1111-1111-111111111111',
					'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
					'1', '2', '999', 'admin', 'test'
				];

				// Check common multi-tenant table patterns
				const tables = ['users', 'organizations', 'workspaces', 'teams', 'accounts', 'tenants'];

				for (const table of tables) {
					for (const tenantId of tenantIds) {
						try {
							const res = await fetch(
								`${context.supabaseUrl}/rest/v1/${table}?or=(tenant_id.eq.${tenantId},organization_id.eq.${tenantId},workspace_id.eq.${tenantId})&limit=1`,
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
								accessibleTables.push(`${table} (tenant: ${tenantId})`);
								break;
							}
						} catch {
							// Table doesn't exist or not accessible
						}
					}
				}

				return {
					breached: accessibleTables.length > 0,
					status: accessibleTables.length > 0 ? 'breached' : 'secure',
					summary: accessibleTables.length > 0
						? `Cross-tenant access possible: ${accessibleTables.join(', ')}`
						: 'Tenant isolation appears intact',
					evidence: accessibleTables.length > 0 ? { tables: accessibleTables } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test tenant isolation' };
			}
		}
	},
	{
		id: 'schema-isolation-bypass',
		name: 'Schema Isolation Bypass',
		description: 'Attempt to access other tenant schemas in multi-schema setup',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			const accessibleSchemas: string[] = [];

			// Common tenant schema patterns
			const schemas = [
				'tenant_1', 'tenant_2', 'tenant_admin',
				'org_1', 'org_default',
				'workspace_1', 'workspace_default',
				'customer_1', 'customer_demo'
			];

			for (const schema of schemas) {
				try {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${schema}.users?limit=1`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) || (data && !data.code)) {
						accessibleSchemas.push(schema);
					}
				} catch {
					// Schema not accessible
				}
			}

			return {
				breached: accessibleSchemas.length > 0,
				status: accessibleSchemas.length > 0 ? 'breached' : 'secure',
				summary: accessibleSchemas.length > 0
					? `Can access tenant schemas: ${accessibleSchemas.join(', ')}`
					: 'Schema isolation intact',
				evidence: accessibleSchemas.length > 0 ? { schemas: accessibleSchemas } : undefined
			};
		}
	},
	{
		id: 'rls-tenant-bypass',
		name: 'RLS Tenant Context Bypass',
		description: 'Check if RLS policies properly check tenant context',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to set tenant context via headers or claims
				const customHeaders = [
					{ 'x-tenant-id': 'admin' },
					{ 'x-organization-id': '1' },
					{ 'x-workspace-id': 'default' }
				];

				const results: string[] = [];

				for (const headers of customHeaders) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/users?limit=10`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`,
								...headers
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (Array.isArray(data) && data.length > 0) {
						results.push(Object.keys(headers)[0]);
					}
				}

				return {
					breached: results.length > 0,
					status: results.length > 0 ? 'breached' : 'secure',
					summary: results.length > 0
						? `Tenant context injectable via: ${results.join(', ')}`
						: 'Tenant context not injectable via headers',
					evidence: results.length > 0 ? { headers: results } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test tenant context' };
			}
		}
	},
	{
		id: 'cross-tenant-join',
		name: 'Cross-Tenant Join Attack',
		description: 'Attempt to join data across tenants via PostgREST',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try embedding queries that might leak cross-tenant data
				const embedQueries = [
					'users?select=*,organizations(*)',
					'posts?select=*,author:users(*)',
					'orders?select=*,customer:customers(*)'
				];

				const leaks: string[] = [];

				for (const query of embedQueries) {
					try {
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
							// Check if embedded data contains different tenant IDs
							const tenantIds = new Set();
							for (const item of data) {
								if (item.tenant_id) tenantIds.add(item.tenant_id);
								if (item.organization_id) tenantIds.add(item.organization_id);
							}
							if (tenantIds.size > 1) {
								leaks.push(query.split('?')[0]);
							}
						}
					} catch {
						// Query failed
					}
				}

				return {
					breached: leaks.length > 0,
					status: leaks.length > 0 ? 'breached' : 'secure',
					summary: leaks.length > 0
						? `Cross-tenant data leak via: ${leaks.join(', ')}`
						: 'No cross-tenant join leaks detected',
					evidence: leaks.length > 0 ? { tables: leaks } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test cross-tenant joins' };
			}
		}
	},
	{
		id: 'tenant-admin-escalation',
		name: 'Tenant Admin Privilege Escalation',
		description: 'Attempt to escalate to tenant admin privileges',
		category: 'auth',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to update user to admin role
				const adminFields = [
					{ is_admin: true },
					{ role: 'admin' },
					{ role: 'tenant_admin' },
					{ permissions: ['admin'] },
					{ is_owner: true }
				];

				for (const fields of adminFields) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/users?id=eq.current`,
						{
							method: 'PATCH',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`,
								'Prefer': 'return=representation'
							},
							body: JSON.stringify(fields),
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) && data.length > 0) {
							return {
								breached: true,
								status: 'breached',
								summary: `Admin escalation possible via: ${Object.keys(fields).join(', ')}`,
								evidence: { fields, result: data[0] }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Admin privilege escalation blocked'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test admin escalation' };
			}
		}
	},
	{
		id: 'tenant-data-export',
		name: 'Tenant Data Mass Export',
		description: 'Check if entire tenant data can be exported without limits',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const tables = ['users', 'posts', 'orders', 'customers', 'transactions'];
				const exportable: Array<{ table: string; count: number }> = [];

				for (const table of tables) {
					try {
						const res = await fetch(
							`${context.supabaseUrl}/rest/v1/${table}?select=*`,
							{
								headers: {
									'apikey': context.anonKey,
									'Authorization': `Bearer ${context.anonKey}`,
									'Range': '0-999' // Try to get 1000 records
								},
								signal: context.signal
							}
						);

						const data = await res.json();
						if (Array.isArray(data) && data.length > 100) {
							exportable.push({ table, count: data.length });
						}
					} catch {
						// Table not accessible
					}
				}

				return {
					breached: exportable.length > 0,
					status: exportable.length > 0 ? 'breached' : 'secure',
					summary: exportable.length > 0
						? `Mass export possible: ${exportable.map(e => `${e.table}(${e.count})`).join(', ')}`
						: 'No mass export vulnerability detected',
					evidence: exportable.length > 0 ? { tables: exportable } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test data export' };
			}
		}
	}
];
