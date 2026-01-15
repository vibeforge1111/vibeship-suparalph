/**
 * Data Exposure Attacks
 * Tests for sensitive data exposure and field-level security issues
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Data Exposure Attack Vectors
 */
export const dataExposureAttacks: AttackVector[] = [
	{
		id: 'data-pii-exposure',
		name: 'PII Data Exposure',
		description: 'Tests if Personally Identifiable Information is exposed via API',
		category: 'rls',
		severity: 'critical',
		tags: ['data', 'pii', 'privacy'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const piiFields = [
				'ssn', 'social_security', 'tax_id', 'national_id',
				'passport', 'drivers_license', 'license_number',
				'date_of_birth', 'dob', 'birth_date',
				'home_address', 'street_address', 'physical_address',
				'phone_number', 'mobile', 'cell_phone',
				'bank_account', 'routing_number', 'account_number',
				'credit_card', 'card_number', 'cvv', 'expiry'
			];

			const tables = ['users', 'profiles', 'customers', 'employees', 'contacts', 'accounts'];
			const exposedPii: Array<{ table: string; fields: string[] }> = [];

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`,
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
							const record = data[0];
							const exposedFields = Object.keys(record).filter(key =>
								piiFields.some(pii => key.toLowerCase().includes(pii))
							);

							if (exposedFields.length > 0) {
								exposedPii.push({ table, fields: exposedFields });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposedPii.length > 0;

			return {
				attackId: 'data-pii-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `PII exposed in ${exposedPii.length} tables - GDPR/CCPA risk!`
					: 'No PII fields exposed via API',
				details: {},
				evidence: breached ? { exposed: exposedPii } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-secrets-in-db',
		name: 'Secrets Stored in Database',
		description: 'Checks if secrets/keys are accessible via API',
		category: 'database',
		severity: 'critical',
		tags: ['data', 'secrets', 'credentials'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const secretTables = ['secrets', 'api_keys', 'tokens', 'credentials', 'keys', 'config', 'settings'];
			const secretFields = ['api_key', 'secret', 'password', 'token', 'private_key', 'credential'];

			const exposedSecrets: Array<{ table: string; hasSecretFields: boolean }> = [];

			for (const table of secretTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`,
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
							const record = data[0];
							const hasSecrets = Object.keys(record).some(key =>
								secretFields.some(secret => key.toLowerCase().includes(secret))
							);

							exposedSecrets.push({ table, hasSecretFields: hasSecrets });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposedSecrets.some(e => e.hasSecretFields);

			return {
				attackId: 'data-secrets-in-db',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'CRITICAL: Secret fields accessible via API!'
					: 'No secret tables exposed',
				details: {},
				evidence: exposedSecrets.length > 0 ? { tables: exposedSecrets } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-password-hashes',
		name: 'Password Hash Exposure',
		description: 'Tests if password hashes are exposed in API responses',
		category: 'auth',
		severity: 'critical',
		tags: ['data', 'password', 'hash'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'accounts', 'auth_users', 'members', 'admins'];
			const passwordFields = ['password', 'password_hash', 'hashed_password', 'encrypted_password', 'pwd'];

			const exposed: Array<{ table: string; field: string }> = [];

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`,
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
							const record = data[0];
							for (const field of Object.keys(record)) {
								if (passwordFields.some(pf => field.toLowerCase().includes(pf))) {
									if (record[field] !== null) {
										exposed.push({ table, field });
									}
								}
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'data-password-hashes',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `CRITICAL: Password hashes exposed in ${exposed.length} locations!`
					: 'Password hashes not exposed',
				details: {},
				evidence: breached ? { exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-email-enumeration',
		name: 'Email Address Enumeration',
		description: 'Tests if email addresses can be enumerated via API',
		category: 'rls',
		severity: 'medium',
		tags: ['data', 'email', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'profiles', 'customers', 'contacts', 'subscribers', 'members'];
			const emailsFound: Array<{ table: string; count: number }> = [];

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=email&limit=100`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data)) {
							const emailCount = data.filter((r: Record<string, unknown>) => r.email).length;
							if (emailCount > 0) {
								emailsFound.push({ table, count: emailCount });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const totalEmails = emailsFound.reduce((sum, e) => sum + e.count, 0);
			const breached = totalEmails > 0;

			return {
				attackId: 'data-email-enumeration',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${totalEmails} email addresses can be enumerated`
					: 'Email addresses not enumerable',
				details: {},
				evidence: breached ? { tables: emailsFound, totalEmails } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-financial-exposure',
		name: 'Financial Data Exposure',
		description: 'Tests if financial information is exposed',
		category: 'rls',
		severity: 'critical',
		tags: ['data', 'financial', 'payment'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const financialTables = ['payments', 'transactions', 'invoices', 'orders', 'billing', 'subscriptions'];
			const sensitiveFields = ['amount', 'total', 'price', 'card_', 'payment_method', 'stripe_', 'paypal_'];

			const exposed: Array<{ table: string; fields: string[]; recordCount: number }> = [];

			for (const table of financialTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=10`,
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
							const record = data[0];
							const foundFields = Object.keys(record).filter(key =>
								sensitiveFields.some(sf => key.toLowerCase().includes(sf))
							);

							if (foundFields.length > 0) {
								exposed.push({
									table,
									fields: foundFields,
									recordCount: data.length
								});
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'data-financial-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Financial data exposed in ${exposed.length} tables - PCI compliance risk!`
					: 'Financial data not exposed',
				details: {},
				evidence: breached ? { exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-internal-ids',
		name: 'Internal ID Exposure',
		description: 'Checks if internal/sequential IDs expose business metrics',
		category: 'api',
		severity: 'low',
		tags: ['data', 'ids', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'orders', 'customers', 'invoices'];
			const sequentialIds: Array<{ table: string; highestId: number }> = [];

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=id&order=id.desc&limit=1`,
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
							const id = data[0].id;
							// Check if it's a sequential integer (not UUID)
							if (typeof id === 'number' && id > 0) {
								sequentialIds.push({ table, highestId: id });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = sequentialIds.length > 0;

			return {
				attackId: 'data-internal-ids',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Sequential IDs expose business metrics in ${sequentialIds.length} tables`
					: 'Using UUIDs or IDs not exposed',
				details: {},
				evidence: breached ? { tables: sequentialIds } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-audit-log-exposure',
		name: 'Audit Log Exposure',
		description: 'Tests if audit logs are accessible to unauthorized users',
		category: 'database',
		severity: 'high',
		tags: ['data', 'audit', 'logs'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const auditTables = [
				'audit_logs', 'logs', 'activity_logs', 'event_logs',
				'access_logs', 'change_history', 'history', 'audit'
			];

			const exposed: Array<{ table: string; count: number }> = [];

			for (const table of auditTables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=10`,
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
							exposed.push({ table, count: data.length });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'data-audit-log-exposure',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Audit logs exposed in ${exposed.length} tables`
					: 'Audit logs properly protected',
				details: {},
				evidence: breached ? { tables: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'data-column-level-security',
		name: 'Column Level Security',
		description: 'Tests if sensitive columns are properly hidden',
		category: 'rls',
		severity: 'high',
		tags: ['data', 'columns', 'security'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const tables = ['users', 'profiles', 'accounts'];
			const sensitiveColumns = [
				'password', 'password_hash', 'secret', 'api_key',
				'private_key', 'token', 'refresh_token', 'session_token',
				'two_factor_secret', 'backup_codes', 'recovery_codes'
			];

			const exposedColumns: Array<{ table: string; columns: string[] }> = [];

			for (const table of tables) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/rest/v1/${table}?select=*&limit=1`,
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
							const record = data[0];
							const sensitiveFound = Object.keys(record).filter(col =>
								sensitiveColumns.some(sc => col.toLowerCase().includes(sc))
							);

							if (sensitiveFound.length > 0) {
								exposedColumns.push({ table, columns: sensitiveFound });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposedColumns.length > 0;

			return {
				attackId: 'data-column-level-security',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Sensitive columns exposed in ${exposedColumns.length} tables`
					: 'Sensitive columns properly protected',
				details: {},
				evidence: breached ? { exposed: exposedColumns } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
