/**
 * Database Attacks
 * Tests for PostgreSQL and Supabase database-level vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Database Attack Vectors
 */
export const databaseAttacks: AttackVector[] = [
	{
		id: 'db-system-tables',
		name: 'System Table Access',
		description: 'Tests if system tables are accessible via REST API',
		category: 'database',
		severity: 'critical',
		tags: ['database', 'system', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const systemTables = [
				'pg_catalog.pg_tables',
				'pg_catalog.pg_roles',
				'information_schema.tables',
				'information_schema.columns',
				'auth.users',
				'storage.buckets',
				'storage.objects'
			];

			const accessible: Array<{ table: string; count: number }> = [];

			for (const table of systemTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=5`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 0) {
							accessible.push({ table, count: data.length });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'db-system-tables',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} system tables accessible!`
					: 'System tables properly protected',
				details: {},
				evidence: breached ? { tables: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-extension-abuse',
		name: 'PostgreSQL Extension Abuse',
		description: 'Tests if dangerous extensions are enabled and accessible',
		category: 'database',
		severity: 'critical',
		tags: ['database', 'extensions', 'rce'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const dangerousFunctions = [
				{ fn: 'pg_read_file', args: "'/etc/passwd'" },
				{ fn: 'pg_ls_dir', args: "'/'" },
				{ fn: 'dblink', args: "'host=localhost'" },
				{ fn: 'copy_to', args: "'test', '/tmp/test'" }
			];

			const vulnerable: Array<{ function: string; result: string }> = [];

			for (const { fn, args } of dangerousFunctions) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${fn}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ path: args })
					});

					if (response.ok) {
						vulnerable.push({ function: fn, result: 'accessible' });
					} else if (response.status !== 404) {
						// Function exists but denied - still worth noting
						vulnerable.push({ function: fn, result: 'exists but denied' });
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.some(v => v.result === 'accessible');

			return {
				attackId: 'db-extension-abuse',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Dangerous PostgreSQL functions accessible!'
					: 'Dangerous extensions properly restricted',
				details: {},
				evidence: vulnerable.length > 0 ? { functions: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-schema-enumeration',
		name: 'Schema Enumeration',
		description: 'Attempts to enumerate all database schemas and tables',
		category: 'database',
		severity: 'medium',
		tags: ['database', 'enumeration', 'recon'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const commonTables = [
				'users', 'accounts', 'profiles', 'sessions', 'tokens',
				'posts', 'comments', 'likes', 'follows', 'messages',
				'orders', 'payments', 'products', 'items', 'carts',
				'settings', 'config', 'secrets', 'api_keys', 'webhooks',
				'logs', 'events', 'analytics', 'metrics', 'audit',
				'files', 'uploads', 'media', 'attachments', 'documents',
				'notifications', 'emails', 'sms', 'push_tokens',
				'roles', 'permissions', 'groups', 'memberships',
				'subscriptions', 'plans', 'invoices', 'billing',
				'todos', 'tasks', 'projects', 'teams', 'workspaces'
			];

			const found: string[] = [];

			for (const table of commonTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=count`,
						{
							method: 'HEAD',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					// 200 or 406 means table exists
					if (response.status === 200 || response.status === 406) {
						found.push(table);
					}
				} catch {
					// Continue
				}
			}

			const breached = found.length > 10; // More than 10 tables enumerable is concerning

			return {
				attackId: 'db-schema-enumeration',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${found.length} tables enumerable - schema exposed`
					: `${found.length} tables found (minimal exposure)`,
				details: {},
				evidence: { tables: found },
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-trigger-bypass',
		name: 'Trigger Bypass via Direct Access',
		description: 'Tests if database triggers can be bypassed',
		category: 'database',
		severity: 'high',
		tags: ['database', 'triggers', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Check if we can bypass audit triggers by using bulk operations
			const tables = ['profiles', 'users', 'orders'];
			const bypassed: string[] = [];

			for (const table of tables) {
				try {
					// Try PATCH with multiple updates - sometimes bypasses row-level triggers
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?id=neq.00000000-0000-0000-0000-000000000000`,
						{
							method: 'PATCH',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`,
								'Content-Type': 'application/json',
								Prefer: 'return=minimal'
							},
							body: JSON.stringify({ updated_at: new Date().toISOString() })
						}
					);

					if (response.ok || response.status === 204) {
						bypassed.push(table);
					}
				} catch {
					// Continue
				}
			}

			const breached = bypassed.length > 0;

			return {
				attackId: 'db-trigger-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Bulk operations may bypass triggers on ${bypassed.length} tables`
					: 'Triggers appear to be enforced',
				details: {},
				evidence: breached ? { tables: bypassed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-function-security-definer',
		name: 'Security Definer Function Abuse',
		description: 'Tests for functions running with elevated privileges',
		category: 'database',
		severity: 'critical',
		tags: ['database', 'functions', 'privilege-escalation'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const potentialFunctions = [
				'get_all_users',
				'admin_action',
				'elevated_query',
				'bypass_rls',
				'service_account_action'
			];

			const found: Array<{ name: string; status: number }> = [];

			for (const fn of potentialFunctions) {
				try {
					const response = await fetch(`${ctx.targetUrl}/rest/v1/rpc/${fn}`, {
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({})
					});

					if (response.status !== 404) {
						found.push({ name: fn, status: response.status });
					}
				} catch {
					// Continue
				}
			}

			const breached = found.some(f => f.status === 200);

			return {
				attackId: 'db-function-security-definer',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Security definer functions accessible to anon users!'
					: 'No elevated functions exposed',
				details: {},
				evidence: found.length > 0 ? { functions: found } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-connection-leak',
		name: 'Database Connection String Leak',
		description: 'Tests if database connection details are leaked in errors',
		category: 'database',
		severity: 'critical',
		tags: ['database', 'connection', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const malformedRequests = [
				{ url: '/rest/v1/nonexistent_table_12345', method: 'GET' },
				{ url: '/rest/v1/rpc/nonexistent_function_12345', method: 'POST' },
				{ url: "/rest/v1/users?id=eq.'malformed", method: 'GET' }
			];

			const leaks: Array<{ request: string; leak: string }> = [];
			const sensitivePatterns = [
				/postgresql:\/\//i,
				/postgres:\/\//i,
				/host=.*port=/i,
				/password/i,
				/connection.*string/i,
				/db\.supabase/i
			];

			for (const { url, method } of malformedRequests) {
				try {
					const response = await fetch(`${ctx.targetUrl}${url}`, {
						method,
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/json'
						},
						body: method === 'POST' ? '{"invalid": }' : undefined
					});

					const text = await response.text();

					for (const pattern of sensitivePatterns) {
						if (pattern.test(text)) {
							leaks.push({ request: `${method} ${url}`, leak: pattern.source });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = leaks.length > 0;

			return {
				attackId: 'db-connection-leak',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Database connection details leaked in error messages!'
					: 'Error messages do not leak connection details',
				details: {},
				evidence: breached ? { leaks } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'db-backup-exposure',
		name: 'Database Backup Exposure',
		description: 'Checks for exposed database backups or dumps',
		category: 'database',
		severity: 'critical',
		tags: ['database', 'backup', 'exposure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const backupPaths = [
				'/backup.sql',
				'/dump.sql',
				'/database.sql',
				'/db.sql',
				'/backup.tar',
				'/backup.tar.gz',
				'/.backup',
				'/db_backup',
				'/pg_dump.sql'
			];

			const found: string[] = [];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			for (const path of backupPaths) {
				try {
					const response = await fetch(`${baseUrl}${path}`, {
						method: 'HEAD'
					});

					if (response.ok || response.status === 403) {
						// 403 means file exists but forbidden - still a finding
						found.push(path);
					}
				} catch {
					// Continue
				}
			}

			const breached = found.length > 0;

			return {
				attackId: 'db-backup-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${found.length} potential backup files detected!`
					: 'No exposed backup files found',
				details: {},
				evidence: breached ? { paths: found } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
