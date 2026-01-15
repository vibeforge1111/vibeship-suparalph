/**
 * SupaRalph Report Generation
 * Generate PDF, JSON, and Markdown reports from scan results
 */

import type { BreachReport, Vulnerability } from '$lib/types/attacks';

/**
 * Report format options
 */
export type ReportFormat = 'json' | 'markdown' | 'html';

/**
 * Report configuration
 */
export interface ReportConfig {
	format: ReportFormat;
	includeEvidence?: boolean;
	includeRecommendations?: boolean;
	includeCompliance?: boolean;
	projectName?: string;
	scanDate?: string;
}

/**
 * OWASP Top 10 2021 Mapping
 */
export const OWASP_MAPPING: Record<string, { id: string; name: string; description: string }> = {
	'rls': { id: 'A01:2021', name: 'Broken Access Control', description: 'Access control enforces policy such that users cannot act outside of their intended permissions.' },
	'auth': { id: 'A07:2021', name: 'Identification and Authentication Failures', description: 'Confirmation of the user\'s identity, authentication, and session management.' },
	'injection': { id: 'A03:2021', name: 'Injection', description: 'User-supplied data is not validated, filtered, or sanitized by the application.' },
	'api': { id: 'A05:2021', name: 'Security Misconfiguration', description: 'Missing appropriate security hardening or improperly configured permissions.' },
	'storage': { id: 'A01:2021', name: 'Broken Access Control', description: 'Unauthorized access to storage resources.' },
	'database': { id: 'A03:2021', name: 'Injection', description: 'Database-level security vulnerabilities.' },
	'vibecoder': { id: 'A04:2021', name: 'Insecure Design', description: 'Missing or ineffective control design in AI-generated code.' },
	'functions': { id: 'A05:2021', name: 'Security Misconfiguration', description: 'Edge function security issues.' },
	'realtime': { id: 'A01:2021', name: 'Broken Access Control', description: 'Unauthorized access to realtime subscriptions.' }
};

/**
 * SOC2 Trust Service Criteria Mapping
 */
export const SOC2_MAPPING: Record<string, { criteria: string; description: string }> = {
	'rls': { criteria: 'CC6.1', description: 'Logical and Physical Access Controls - The entity implements logical access security software.' },
	'auth': { criteria: 'CC6.1', description: 'Logical and Physical Access Controls - Authentication mechanisms.' },
	'storage': { criteria: 'CC6.7', description: 'Data Classification and Protection - Information assets are identified and classified.' },
	'api': { criteria: 'CC6.6', description: 'System Operations - Security events are identified and evaluated.' },
	'database': { criteria: 'CC6.1', description: 'Logical and Physical Access Controls - Database access restrictions.' }
};

/**
 * GDPR Article Mapping
 */
export const GDPR_MAPPING: Record<string, { article: string; description: string }> = {
	'rls': { article: 'Article 32', description: 'Security of processing - Implement appropriate technical measures.' },
	'auth': { article: 'Article 32', description: 'Security of processing - Ensure confidentiality and integrity.' },
	'data-exposure': { article: 'Article 33', description: 'Notification of a personal data breach.' },
	'storage': { article: 'Article 32', description: 'Security of processing - Protection of stored data.' }
};

/**
 * Generate a JSON report
 */
export function generateJSONReport(report: BreachReport, config: ReportConfig = { format: 'json' }): string {
	const jsonReport = {
		meta: {
			generator: 'SupaRalph Security Scanner',
			version: '1.0.0',
			generatedAt: new Date().toISOString(),
			projectName: config.projectName || report.projectName || 'Unknown Project',
			scanDate: config.scanDate || report.startedAt
		},
		summary: {
			totalAttacks: report.stats.total,
			breached: report.stats.breached,
			secure: report.stats.secure,
			errors: report.stats.error,
			skipped: report.stats.skipped,
			vulnerabilityCount: report.vulnerabilities.length,
			riskScore: calculateRiskScore(report.vulnerabilities)
		},
		vulnerabilities: report.vulnerabilities.map(v => ({
			id: v.id,
			attackId: v.attackId,
			title: v.title,
			severity: v.severity,
			category: v.category,
			description: v.description,
			impact: v.impact,
			fix: config.includeRecommendations ? v.fix : undefined,
			evidence: config.includeEvidence ? v.evidence : undefined,
			compliance: config.includeCompliance ? {
				owasp: OWASP_MAPPING[v.category],
				soc2: SOC2_MAPPING[v.category],
				gdpr: GDPR_MAPPING[v.category]
			} : undefined,
			discoveredAt: v.discoveredAt
		})),
		byCategory: report.byCategory,
		bySeverity: report.bySeverity,
		compliance: config.includeCompliance ? {
			owasp: getOWASPSummary(report.vulnerabilities),
			soc2: getSOC2Summary(report.vulnerabilities),
			gdpr: getGDPRSummary(report.vulnerabilities)
		} : undefined
	};

	return JSON.stringify(jsonReport, null, 2);
}

/**
 * Generate a Markdown report
 */
export function generateMarkdownReport(report: BreachReport, config: ReportConfig = { format: 'markdown' }): string {
	const lines: string[] = [];
	const riskScore = calculateRiskScore(report.vulnerabilities);

	// Header
	lines.push('# SupaRalph Security Scan Report');
	lines.push('');
	lines.push(`**Project:** ${config.projectName || report.projectName || 'Unknown Project'}`);
	lines.push(`**Scan Date:** ${new Date(report.startedAt || Date.now()).toLocaleString()}`);
	lines.push(`**Generated:** ${new Date().toLocaleString()}`);
	lines.push('');

	// Executive Summary
	lines.push('## Executive Summary');
	lines.push('');
	lines.push(`| Metric | Value |`);
	lines.push(`|--------|-------|`);
	lines.push(`| Total Attacks | ${report.stats.total} |`);
	lines.push(`| Vulnerabilities Found | ${report.stats.breached} |`);
	lines.push(`| Secure | ${report.stats.secure} |`);
	lines.push(`| Risk Score | ${riskScore}/100 |`);
	lines.push('');

	// Risk Level
	const riskLevel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';
	lines.push(`**Overall Risk Level:** ${riskLevel}`);
	lines.push('');

	// Vulnerabilities by Severity
	lines.push('## Vulnerabilities by Severity');
	lines.push('');
	lines.push('| Severity | Count |');
	lines.push('|----------|-------|');
	for (const [severity, data] of Object.entries(report.bySeverity)) {
		if (data.breached > 0) {
			lines.push(`| ${severity.toUpperCase()} | ${data.breached} |`);
		}
	}
	lines.push('');

	// Vulnerabilities by Category
	lines.push('## Vulnerabilities by Category');
	lines.push('');
	lines.push('| Category | Breached | Secure |');
	lines.push('|----------|----------|--------|');
	for (const [category, data] of Object.entries(report.byCategory)) {
		if (data.total > 0) {
			lines.push(`| ${category.toUpperCase()} | ${data.breached} | ${data.secure} |`);
		}
	}
	lines.push('');

	// Detailed Findings
	lines.push('## Detailed Findings');
	lines.push('');

	const criticalVulns = report.vulnerabilities.filter(v => v.severity === 'critical');
	const highVulns = report.vulnerabilities.filter(v => v.severity === 'high');
	const mediumVulns = report.vulnerabilities.filter(v => v.severity === 'medium');
	const lowVulns = report.vulnerabilities.filter(v => v.severity === 'low');

	if (criticalVulns.length > 0) {
		lines.push('### Critical Vulnerabilities');
		lines.push('');
		for (const vuln of criticalVulns) {
			lines.push(formatVulnerabilityMarkdown(vuln, config));
		}
	}

	if (highVulns.length > 0) {
		lines.push('### High Vulnerabilities');
		lines.push('');
		for (const vuln of highVulns) {
			lines.push(formatVulnerabilityMarkdown(vuln, config));
		}
	}

	if (mediumVulns.length > 0) {
		lines.push('### Medium Vulnerabilities');
		lines.push('');
		for (const vuln of mediumVulns) {
			lines.push(formatVulnerabilityMarkdown(vuln, config));
		}
	}

	if (lowVulns.length > 0) {
		lines.push('### Low Vulnerabilities');
		lines.push('');
		for (const vuln of lowVulns) {
			lines.push(formatVulnerabilityMarkdown(vuln, config));
		}
	}

	// Compliance Section
	if (config.includeCompliance) {
		lines.push('## Compliance Mapping');
		lines.push('');

		lines.push('### OWASP Top 10 2021');
		lines.push('');
		const owaspSummary = getOWASPSummary(report.vulnerabilities);
		for (const [id, count] of Object.entries(owaspSummary)) {
			const mapping = Object.values(OWASP_MAPPING).find(m => m.id === id);
			if (mapping && count > 0) {
				lines.push(`- **${id}** ${mapping.name}: ${count} issue(s)`);
			}
		}
		lines.push('');

		lines.push('### SOC2 Trust Service Criteria');
		lines.push('');
		const soc2Summary = getSOC2Summary(report.vulnerabilities);
		for (const [criteria, count] of Object.entries(soc2Summary)) {
			if (count > 0) {
				lines.push(`- **${criteria}**: ${count} issue(s)`);
			}
		}
		lines.push('');
	}

	// Recommendations
	if (config.includeRecommendations) {
		lines.push('## Recommendations');
		lines.push('');
		lines.push('1. **Immediate Actions** - Fix all CRITICAL and HIGH severity issues');
		lines.push('2. **Review RLS Policies** - Ensure all tables have proper Row Level Security');
		lines.push('3. **Audit Service Keys** - Verify no service_role keys are exposed');
		lines.push('4. **Enable MFA** - Require multi-factor authentication for admin users');
		lines.push('5. **Regular Scanning** - Run SupaRalph scans on every deployment');
		lines.push('');
	}

	// Footer
	lines.push('---');
	lines.push('');
	lines.push('*Generated by SupaRalph Security Scanner*');
	lines.push('');
	lines.push('**How to Fix:** Copy your findings and paste them into [Supabase SQL Editor](https://supabase.com/dashboard/project/_/sql/new) with the AI Assistant to get tailored SQL fixes for your schema.');

	return lines.join('\n');
}

/**
 * Generate an HTML report
 */
export function generateHTMLReport(report: BreachReport, config: ReportConfig = { format: 'html' }): string {
	const riskScore = calculateRiskScore(report.vulnerabilities);
	const riskLevel = riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';
	const riskColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>SupaRalph Security Report</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
		.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
		h1, h2, h3 { color: #f8fafc; margin-bottom: 1rem; }
		h1 { font-size: 2rem; border-bottom: 2px solid #3ecf8e; padding-bottom: 0.5rem; }
		h2 { font-size: 1.5rem; margin-top: 2rem; }
		.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
		.logo { color: #3ecf8e; font-weight: bold; font-size: 1.5rem; }
		.risk-badge { padding: 0.5rem 1rem; font-weight: bold; text-transform: uppercase; }
		.risk-critical { background: #ef4444; }
		.risk-high { background: #f97316; }
		.risk-medium { background: #eab308; color: #0f172a; }
		.risk-low { background: #22c55e; }
		.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
		.stat-card { background: #1e293b; padding: 1.5rem; border-left: 4px solid #3ecf8e; }
		.stat-value { font-size: 2rem; font-weight: bold; color: #3ecf8e; }
		.stat-label { color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; }
		.vuln-card { background: #1e293b; margin: 1rem 0; padding: 1.5rem; border-left: 4px solid; }
		.vuln-critical { border-color: #ef4444; }
		.vuln-high { border-color: #f97316; }
		.vuln-medium { border-color: #eab308; }
		.vuln-low { border-color: #22c55e; }
		.vuln-title { font-size: 1.1rem; font-weight: bold; margin-bottom: 0.5rem; }
		.vuln-meta { font-size: 0.875rem; color: #94a3b8; margin-bottom: 0.5rem; }
		.badge { display: inline-block; padding: 0.25rem 0.5rem; font-size: 0.75rem; font-weight: bold; margin-right: 0.5rem; }
		.badge-critical { background: #ef4444; }
		.badge-high { background: #f97316; }
		.badge-medium { background: #eab308; color: #0f172a; }
		.badge-low { background: #22c55e; }
		table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
		th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; }
		th { background: #1e293b; color: #3ecf8e; }
		code { background: #1e293b; padding: 0.125rem 0.25rem; font-family: monospace; }
		.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #334155; text-align: center; color: #64748b; }
		.cta { background: #3ecf8e; color: #0f172a; padding: 1rem 2rem; display: inline-block; text-decoration: none; font-weight: bold; margin-top: 1rem; }
		.cta:hover { background: #2eb97a; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<div class="logo">SupaRalph</div>
			<span class="risk-badge risk-${riskLevel}">Risk: ${riskLevel.toUpperCase()}</span>
		</div>

		<h1>Security Scan Report</h1>
		<p><strong>Project:</strong> ${config.projectName || report.projectName || 'Unknown Project'}</p>
		<p><strong>Scan Date:</strong> ${new Date(report.startedAt || Date.now()).toLocaleString()}</p>

		<div class="summary">
			<div class="stat-card">
				<div class="stat-value">${report.stats.total}</div>
				<div class="stat-label">Total Attacks</div>
			</div>
			<div class="stat-card" style="border-color: #ef4444;">
				<div class="stat-value" style="color: #ef4444;">${report.stats.breached}</div>
				<div class="stat-label">Vulnerabilities</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">${report.stats.secure}</div>
				<div class="stat-label">Secure</div>
			</div>
			<div class="stat-card">
				<div class="stat-value">${riskScore}</div>
				<div class="stat-label">Risk Score /100</div>
			</div>
		</div>

		<h2>Vulnerabilities Found</h2>
		${report.vulnerabilities.map(v => `
		<div class="vuln-card vuln-${v.severity}">
			<span class="badge badge-${v.severity}">${v.severity.toUpperCase()}</span>
			<span class="badge" style="background: #334155;">${v.category.toUpperCase()}</span>
			<div class="vuln-title">${v.title}</div>
			<div class="vuln-meta">${v.description}</div>
			${v.impact ? `<p><strong>Impact:</strong> ${v.impact}</p>` : ''}
		</div>
		`).join('')}

		<h2>How to Fix</h2>
		<p>Copy your vulnerability findings and paste them into Supabase SQL Editor with the AI Assistant. The AI has full context of your schema and can generate exact SQL fixes.</p>
		<a href="https://supabase.com/dashboard/project/_/sql/new" target="_blank" class="cta">Open Supabase SQL Editor</a>

		<div class="footer">
			<p>Generated by SupaRalph Security Scanner</p>
			<p>For authorized security testing only</p>
		</div>
	</div>
</body>
</html>`;
}

/**
 * Format a vulnerability for Markdown
 */
function formatVulnerabilityMarkdown(vuln: Vulnerability, config: ReportConfig): string {
	const lines: string[] = [];

	lines.push(`#### ${vuln.title}`);
	lines.push('');
	lines.push(`- **Severity:** ${vuln.severity.toUpperCase()}`);
	lines.push(`- **Category:** ${vuln.category}`);
	lines.push(`- **Description:** ${vuln.description}`);

	if (vuln.impact) {
		lines.push(`- **Impact:** ${vuln.impact}`);
	}

	if (config.includeRecommendations && vuln.fix) {
		lines.push('');
		lines.push('**Fix:**');
		if (vuln.fix.summary) {
			lines.push(`${vuln.fix.summary}`);
		}
		if (vuln.fix.steps) {
			for (const step of vuln.fix.steps) {
				lines.push(`- ${step}`);
			}
		}
	}

	if (config.includeEvidence && vuln.evidence) {
		lines.push('');
		lines.push('**Evidence:**');
		lines.push('```json');
		lines.push(JSON.stringify(vuln.evidence, null, 2));
		lines.push('```');
	}

	lines.push('');
	return lines.join('\n');
}

/**
 * Calculate risk score (0-100)
 */
export function calculateRiskScore(vulnerabilities: Vulnerability[]): number {
	if (vulnerabilities.length === 0) return 0;

	const severityWeights = {
		critical: 40,
		high: 25,
		medium: 10,
		low: 5
	};

	let totalScore = 0;
	for (const vuln of vulnerabilities) {
		totalScore += severityWeights[vuln.severity] || 5;
	}

	return Math.min(100, totalScore);
}

/**
 * Get OWASP summary
 */
function getOWASPSummary(vulnerabilities: Vulnerability[]): Record<string, number> {
	const summary: Record<string, number> = {};

	for (const vuln of vulnerabilities) {
		const mapping = OWASP_MAPPING[vuln.category];
		if (mapping) {
			summary[mapping.id] = (summary[mapping.id] || 0) + 1;
		}
	}

	return summary;
}

/**
 * Get SOC2 summary
 */
function getSOC2Summary(vulnerabilities: Vulnerability[]): Record<string, number> {
	const summary: Record<string, number> = {};

	for (const vuln of vulnerabilities) {
		const mapping = SOC2_MAPPING[vuln.category];
		if (mapping) {
			summary[mapping.criteria] = (summary[mapping.criteria] || 0) + 1;
		}
	}

	return summary;
}

/**
 * Get GDPR summary
 */
function getGDPRSummary(vulnerabilities: Vulnerability[]): Record<string, number> {
	const summary: Record<string, number> = {};

	for (const vuln of vulnerabilities) {
		const mapping = GDPR_MAPPING[vuln.category];
		if (mapping) {
			summary[mapping.article] = (summary[mapping.article] || 0) + 1;
		}
	}

	return summary;
}

/**
 * Download report as file
 */
export function downloadReport(content: string, filename: string, mimeType: string): void {
	const blob = new Blob([content], { type: mimeType });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	URL.revokeObjectURL(url);
}
