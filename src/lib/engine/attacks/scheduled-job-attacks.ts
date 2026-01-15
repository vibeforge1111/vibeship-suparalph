/**
 * Scheduled Job (pg_cron) attacks
 * Tests for cron job vulnerabilities in Supabase
 */

import type { AttackVector } from '$lib/types/attacks';

export const scheduledJobAttacks: AttackVector[] = [
	{
		id: 'cron-job-enumeration',
		name: 'Cron Job Enumeration',
		description: 'Attempt to enumerate scheduled jobs via cron schema',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Try to access cron.job table
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/cron.job?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && !data.code;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? `Cron jobs exposed: ${data.length} jobs visible`
						: 'Cron jobs properly protected',
					evidence: hasAccess ? { jobCount: data.length, jobs: data.map((j: { jobname: string }) => j.jobname) } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cron schema not accessible' };
			}
		}
	},
	{
		id: 'cron-job-injection',
		name: 'Cron Job SQL Injection',
		description: 'Attempt to inject malicious SQL via cron job creation',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to call cron.schedule function
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/rpc/cron.schedule`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							job_name: 'supashield_test',
							schedule: '* * * * *',
							command: 'SELECT 1'
						}),
						signal: context.signal
					}
				);

				const data = await res.json();
				const canSchedule = res.ok && !data.error;

				return {
					breached: canSchedule,
					status: canSchedule ? 'breached' : 'secure',
					summary: canSchedule
						? 'CRITICAL: Can create cron jobs - code execution possible!'
						: 'Cron job creation properly restricted',
					evidence: canSchedule ? data : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cron functions not accessible' };
			}
		}
	},
	{
		id: 'cron-job-history',
		name: 'Cron Job History Exposure',
		description: 'Check if cron job execution history is accessible',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/cron.job_run_details?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && !data.code;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? `Cron history exposed: ${data.length} execution records`
						: 'Cron history protected',
					evidence: hasAccess ? { recordCount: data.length } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cron history not accessible' };
			}
		}
	},
	{
		id: 'cron-unschedule-attack',
		name: 'Cron Job Unschedule Attack',
		description: 'Attempt to disable scheduled jobs',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/rpc/cron.unschedule`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							job_name: 'nonexistent_job_test'
						}),
						signal: context.signal
					}
				);

				// If we don't get a permission error, function is accessible
				const data = await res.json();
				const canUnschedule = !data?.message?.includes('permission') &&
					!data?.message?.includes('denied') &&
					res.status !== 403;

				return {
					breached: canUnschedule,
					status: canUnschedule ? 'breached' : 'secure',
					summary: canUnschedule
						? 'Can potentially unschedule cron jobs!'
						: 'Cron unschedule properly restricted',
					evidence: canUnschedule ? { response: data } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cron unschedule not accessible' };
			}
		}
	},
	{
		id: 'pgagent-job-access',
		name: 'pgAgent Job Access',
		description: 'Check for pgAgent job scheduler access',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			try {
				// Check pgagent schema tables
				const tables = ['pgagent.pga_job', 'pgagent.pga_schedule', 'pgagent.pga_jobstep'];
				const accessible: string[] = [];

				for (const table of tables) {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/${table}?select=*&limit=1`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const data = await res.json();
					if (!data?.code && !data?.message) {
						accessible.push(table);
					}
				}

				return {
					breached: accessible.length > 0,
					status: accessible.length > 0 ? 'breached' : 'secure',
					summary: accessible.length > 0
						? `pgAgent tables exposed: ${accessible.join(', ')}`
						: 'pgAgent schema protected',
					evidence: accessible.length > 0 ? { tables: accessible } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pgAgent not accessible' };
			}
		}
	}
];
