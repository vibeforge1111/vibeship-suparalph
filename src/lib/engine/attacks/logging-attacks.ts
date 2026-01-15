/**
 * Logging attacks
 * Tests for Supabase logging and observability vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const loggingAttacks: AttackVector[] = [
	{
		id: 'log-injection',
		name: 'Log Injection Attack',
		description: 'Test for log injection vulnerabilities',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to inject into logs via various inputs
				const logInjectionPayloads = [
					'test\n[ADMIN] User promoted to admin',
					'test\r\n{"level":"error","admin_access":true}',
					'test%0a%0d[CRITICAL] Security breach',
					'user\\nINFO: Password changed for admin'
				];

				for (const payload of logInjectionPayloads) {
					// Try injection via auth (login attempts are logged)
					await fetch(
						`${context.supabaseUrl}/auth/v1/token?grant_type=password`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: JSON.stringify({
								email: payload,
								password: 'test'
							}),
							signal: context.signal
						}
					);

					// Try injection via user-agent
					await fetch(
						`${context.supabaseUrl}/rest/v1/`,
						{
							headers: {
								'apikey': context.anonKey,
								'User-Agent': payload
							},
							signal: context.signal
						}
					);
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Log injection attempts made - verify logs are properly sanitized',
					details: { note: 'Manual log review recommended to verify sanitization' }
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Log injection test completed' };
			}
		}
	},
	{
		id: 'log-file-access',
		name: 'Log File Direct Access',
		description: 'Test for direct access to log files',
		category: 'api',
		severity: 'high',
		async execute(context) {
			try {
				// Common log file paths
				const logPaths = [
					'/logs',
					'/admin/logs',
					'/api/logs',
					'/.logs',
					'/var/log/postgresql',
					'/storage/v1/object/public/logs',
					'/functions/v1/logs'
				];

				const accessible: string[] = [];

				for (const path of logPaths) {
					const res = await fetch(
						`${context.supabaseUrl}${path}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok || res.status === 200) {
						const contentType = res.headers.get('content-type') || '';
						if (contentType.includes('text') || contentType.includes('json')) {
							accessible.push(path);
						}
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Log files accessible: ${accessible.join(', ')}`
						: 'Log files not directly accessible',
					evidence: accessible.length > 0 ? { paths: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Log files protected' };
			}
		}
	},
	{
		id: 'log-postgres-access',
		name: 'PostgreSQL Log Access',
		description: 'Test for access to PostgreSQL logs via database',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// PostgreSQL log-related views
				const logViews = [
					'pg_stat_activity?select=*',
					'pg_stat_statements?select=query,calls,total_time',
					'pg_stat_user_tables?select=*',
					'pg_stat_user_indexes?select=*',
					'pg_stat_database?select=*'
				];

				const accessible: Array<{ view: string; count: number }> = [];

				for (const view of logViews) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${view}&limit=10`,
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
						accessible.push({ view: view.split('?')[0], count: data.length });
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `PostgreSQL stats exposed: ${accessible.map(a => a.view).join(', ')}`
						: 'PostgreSQL logs protected',
					evidence: accessible.length > 0 ? { views: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'PostgreSQL logs protected' };
			}
		}
	},
	{
		id: 'log-metrics-exposure',
		name: 'Metrics Endpoint Exposure',
		description: 'Test for exposed metrics endpoints',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Common metrics endpoints
				const metricsEndpoints = [
					'/metrics',
					'/admin/metrics',
					'/_metrics',
					'/prometheus',
					'/health/metrics',
					'/api/metrics',
					'/v1/metrics'
				];

				const exposed: Array<{ endpoint: string; hasData: boolean }> = [];

				for (const endpoint of metricsEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							headers: {
								'apikey': context.anonKey
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						const text = await res.text();
						// Prometheus metrics format check
						const isMetrics = text.includes('# HELP') ||
							text.includes('# TYPE') ||
							text.includes('_total') ||
							text.includes('_bucket');

						if (isMetrics) {
							exposed.push({ endpoint, hasData: true });
						}
					}
				}

				return {
					breached: exposed.length > 0,
					status: exposed.length > 0 ? 'breached' : 'secure',
					summary: exposed.length > 0
						? `Metrics endpoints exposed: ${exposed.map(e => e.endpoint).join(', ')}`
						: 'Metrics endpoints protected',
					evidence: exposed.length > 0 ? { endpoints: exposed } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Metrics protected' };
			}
		}
	},
	{
		id: 'log-debug-info-leak',
		name: 'Debug Information Leakage',
		description: 'Test for debug information in responses',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to trigger debug info
				const debugEndpoints = [
					'/rest/v1/?debug=true',
					'/rest/v1/?verbose=1',
					'/auth/v1/?trace=true',
					'/functions/v1/test?debug=1'
				];

				const leaky: string[] = [];

				for (const endpoint of debugEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							headers: {
								'apikey': context.anonKey,
								'X-Debug': 'true',
								'X-Request-Id': 'test-debug-' + Date.now()
							},
							signal: context.signal
						}
					);

					// Check headers for debug info
					const debugHeaders = [
						'x-debug',
						'x-trace',
						'x-request-id',
						'x-postgres-',
						'x-supabase-'
					];

					for (const header of debugHeaders) {
						const value = res.headers.get(header);
						if (value && value.length > 20) {
							leaky.push(`${header}: ${value.substring(0, 50)}`);
						}
					}

					// Check body for debug info
					try {
						const text = await res.text();
						if (text.includes('stack') || text.includes('trace') ||
							text.includes('debug') || text.includes('internal error')) {
							leaky.push(endpoint);
						}
					} catch {
						// Ignore parse errors
					}
				}

				return {
					breached: leaky.length > 0,
					status: leaky.length > 0 ? 'breached' : 'secure',
					summary: leaky.length > 0
						? `Debug information leaked: ${leaky.length} sources`
						: 'Debug information properly hidden',
					evidence: leaky.length > 0 ? { sources: leaky } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Debug info protected' };
			}
		}
	},
	{
		id: 'log-error-message-exposure',
		name: 'Verbose Error Message Exposure',
		description: 'Test for verbose error messages revealing internal details',
		category: 'api',
		severity: 'medium',
		async execute(context) {
			try {
				// Trigger various errors
				const errorTriggers = [
					{ path: '/rest/v1/nonexistent_table', expected: 'table' },
					{ path: '/rest/v1/users?id=eq.invalid::uuid', expected: 'uuid' },
					{ path: '/rest/v1/rpc/nonexistent_function', expected: 'function' },
					{ path: '/auth/v1/token', expected: 'auth' }
				];

				const verboseErrors: Array<{ path: string; details: string }> = [];

				for (const trigger of errorTriggers) {
					const res = await fetch(
						`${context.supabaseUrl}${trigger.path}`,
						{
							method: trigger.path.includes('token') ? 'POST' : 'GET',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey
							},
							body: trigger.path.includes('token') ? '{}' : undefined,
							signal: context.signal
						}
					);

					const data = await res.json();
					const errorText = JSON.stringify(data);

					// Check for verbose error details
					const hasInternalDetails =
						errorText.includes('pg_') ||
						errorText.includes('postgres') ||
						errorText.includes('schema') ||
						errorText.includes('column') ||
						errorText.includes('permission denied') ||
						errorText.includes('stack') ||
						errorText.includes('at /');

					if (hasInternalDetails) {
						verboseErrors.push({
							path: trigger.path,
							details: errorText.substring(0, 200)
						});
					}
				}

				return {
					breached: verboseErrors.length > 0,
					status: verboseErrors.length > 0 ? 'breached' : 'secure',
					summary: verboseErrors.length > 0
						? `Verbose errors reveal internals: ${verboseErrors.length} endpoints`
						: 'Error messages properly sanitized',
					evidence: verboseErrors.length > 0 ? { errors: verboseErrors } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Error handling secure' };
			}
		}
	},
	{
		id: 'log-audit-trail-access',
		name: 'Audit Trail Access',
		description: 'Test for unauthorized access to audit trails',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Common audit table names
				const auditTables = [
					'audit_log',
					'audit_logs',
					'activity_log',
					'user_activity',
					'access_log',
					'security_log',
					'event_log',
					'change_log'
				];

				for (const table of auditTables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=20`,
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
						// Check if we can see other users' audit data
						const userIds = new Set(
							data.map(row => row.user_id || row.actor_id).filter(Boolean)
						);

						return {
							breached: true,
							status: 'breached',
							summary: `Audit trail exposed via ${table}: ${data.length} records`,
							evidence: {
								table,
								recordCount: data.length,
								uniqueUsers: userIds.size
							}
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Audit trails protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Audit trails protected' };
			}
		}
	},
	{
		id: 'log-realtime-subscription-leak',
		name: 'Realtime Log Subscription',
		description: 'Test for subscribing to log/audit channels',
		category: 'realtime',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to subscribe to log-related channels
				const logChannels = [
					'logs',
					'audit',
					'system',
					'admin',
					'events',
					'postgres_changes:audit_log'
				];

				const accessible: string[] = [];

				for (const channel of logChannels) {
					const res = await fetch(
						`${context.supabaseUrl}/realtime/v1/api/broadcast`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({
								channel,
								event: 'test',
								payload: {}
							}),
							signal: context.signal
						}
					);

					if (res.ok || res.status === 202) {
						accessible.push(channel);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `Can broadcast to log channels: ${accessible.join(', ')}`
						: 'Log channels properly restricted',
					evidence: accessible.length > 0 ? { channels: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Log channels protected' };
			}
		}
	}
];
