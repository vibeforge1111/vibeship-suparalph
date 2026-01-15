/**
 * Backup/Recovery attacks
 * Tests for Supabase backup and recovery vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const backupRecoveryAttacks: AttackVector[] = [
	{
		id: 'backup-pitr-access',
		name: 'Point-in-Time Recovery Access',
		description: 'Check for unauthorized PITR access',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Check for PITR-related endpoints and tables
				const pitrEndpoints = [
					'/rest/v1/rpc/pg_create_restore_point',
					'/rest/v1/rpc/pg_switch_wal',
					'/rest/v1/pg_stat_archiver?select=*',
					'/admin/v1/projects/backups',
					'/admin/v1/pitr'
				];

				const accessible: string[] = [];

				for (const endpoint of pitrEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							method: endpoint.includes('rpc') ? 'POST' : 'GET',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: endpoint.includes('rpc') ? '{}' : undefined,
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
						? `PITR endpoints accessible: ${accessible.join(', ')}`
						: 'PITR endpoints properly protected',
					evidence: accessible.length > 0 ? { endpoints: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'PITR access protected' };
			}
		}
	},
	{
		id: 'backup-enumeration',
		name: 'Backup Enumeration',
		description: 'Test for backup file/configuration enumeration',
		category: 'storage',
		severity: 'high',
		async execute(context) {
			try {
				// Check for backup-related storage or endpoints
				const backupLocations = [
					'/storage/v1/object/public/backups',
					'/storage/v1/object/list/backups',
					'/rest/v1/backups?select=*',
					'/rest/v1/backup_history?select=*',
					'/rest/v1/pg_stat_progress_basebackup?select=*'
				];

				for (const location of backupLocations) {
					const res = await fetch(
						`${context.supabaseUrl}${location}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (data && (Array.isArray(data) ? data.length > 0 : Object.keys(data).length > 0)) {
							return {
								breached: true,
								status: 'breached',
								summary: `Backup data exposed via ${location}`,
								evidence: { location }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Backup information protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Backups not enumerable' };
			}
		}
	},
	{
		id: 'backup-snapshot-access',
		name: 'Database Snapshot Access',
		description: 'Test for unauthorized snapshot access',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Check for snapshot-related access
				const snapshotEndpoints = [
					'pg_snapshot?select=*',
					'pg_export_snapshot',
					'snapshots?select=*',
					'rpc/pg_current_snapshot'
				];

				for (const endpoint of snapshotEndpoints) {
					const isRpc = endpoint.startsWith('rpc/');
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${endpoint}`,
						{
							method: isRpc ? 'POST' : 'GET',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: isRpc ? '{}' : undefined,
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (data && !data.code) {
							return {
								breached: true,
								status: 'breached',
								summary: `Snapshot access via ${endpoint}`,
								evidence: { endpoint }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Snapshot access protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Snapshots protected' };
			}
		}
	},
	{
		id: 'backup-restore-trigger',
		name: 'Unauthorized Restore Trigger',
		description: 'Test if restore operations can be triggered',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to trigger restore operations
				const restoreEndpoints = [
					{ path: '/admin/v1/projects/restore', method: 'POST' },
					{ path: '/rest/v1/rpc/restore_backup', method: 'POST' },
					{ path: '/rest/v1/rpc/pg_restore', method: 'POST' }
				];

				for (const endpoint of restoreEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint.path}`,
						{
							method: endpoint.method,
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({ backup_id: 'test' }),
							signal: context.signal
						}
					);

					// Any non-403/404 response is concerning
					if (res.status !== 403 && res.status !== 404) {
						return {
							breached: true,
							status: 'breached',
							summary: `Restore endpoint accessible: ${endpoint.path} (${res.status})`,
							evidence: { endpoint: endpoint.path, status: res.status }
						};
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Restore operations properly protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Restore endpoints protected' };
			}
		}
	},
	{
		id: 'backup-wal-archive-access',
		name: 'WAL Archive Access',
		description: 'Test for WAL archive file access',
		category: 'storage',
		severity: 'high',
		async execute(context) {
			try {
				// Check for WAL archive access
				const walEndpoints = [
					'/storage/v1/object/public/wal',
					'/storage/v1/object/public/wal_archive',
					'/storage/v1/object/list/wal',
					'/rest/v1/pg_stat_wal?select=*',
					'/rest/v1/pg_stat_wal_receiver?select=*'
				];

				const accessible: string[] = [];

				for (const endpoint of walEndpoints) {
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

					if (res.ok) {
						accessible.push(endpoint);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `WAL archive accessible: ${accessible.join(', ')}`
						: 'WAL archive protected',
					evidence: accessible.length > 0 ? { endpoints: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'WAL archives protected' };
			}
		}
	},
	{
		id: 'backup-retention-policy-exposure',
		name: 'Backup Retention Policy Exposure',
		description: 'Check if backup retention policies are exposed',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				// Check for backup policy configurations
				const policyEndpoints = [
					'backup_policies?select=*',
					'retention_policies?select=*',
					'project_settings?select=backup_config',
					'rpc/get_backup_config'
				];

				for (const endpoint of policyEndpoints) {
					const isRpc = endpoint.startsWith('rpc/');
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${endpoint}`,
						{
							method: isRpc ? 'POST' : 'GET',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: isRpc ? '{}' : undefined,
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						if (Array.isArray(data) ? data.length > 0 : (data && !data.code)) {
							return {
								breached: true,
								status: 'breached',
								summary: `Backup policies exposed via ${endpoint}`,
								evidence: { endpoint }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Backup policies protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Backup policies not exposed' };
			}
		}
	},
	{
		id: 'backup-download-link-exposure',
		name: 'Backup Download Link Exposure',
		description: 'Test for exposed backup download links',
		category: 'storage',
		severity: 'critical',
		async execute(context) {
			try {
				// Check for backup download endpoints
				const downloadEndpoints = [
					'/admin/v1/projects/backups/download',
					'/rest/v1/rpc/get_backup_download_url',
					'/storage/v1/object/sign/backups'
				];

				for (const endpoint of downloadEndpoints) {
					const res = await fetch(
						`${context.supabaseUrl}${endpoint}`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({ backup_id: 'latest' }),
							signal: context.signal
						}
					);

					if (res.ok) {
						const data = await res.json();
						const hasUrl = data?.url || data?.download_url || data?.signedURL;

						if (hasUrl) {
							return {
								breached: true,
								status: 'breached',
								summary: 'Backup download links accessible!',
								evidence: { endpoint, hasUrl: true }
							};
						}
					}
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Backup downloads properly protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Backup downloads protected' };
			}
		}
	}
];
