/**
 * Breach Engine - Core attack orchestration
 * Runs attacks against target Supabase projects
 */

import type {
	AttackVector,
	AttackContext,
	AttackResult,
	AttackStatus,
	BreachReport,
	Vulnerability,
	AttackCategory,
	AttackSeverity
} from '$lib/types/attacks';
import { ATTACK_CATEGORIES, SEVERITY_LEVELS } from '$lib/types/attacks';

export interface BreachEngineConfig {
	// Max concurrent attacks
	concurrency: number;
	// Timeout per attack in ms
	attackTimeout: number;
	// Delay between attacks in ms
	delayBetweenAttacks: number;
	// Stop on first breach?
	stopOnBreach: boolean;
	// Categories to test
	categories?: AttackCategory[];
	// Min severity to test
	minSeverity?: AttackSeverity;
}

export interface BreachEngineCallbacks {
	onAttackStart?: (attack: AttackVector) => void;
	onAttackComplete?: (attack: AttackVector, result: AttackResult) => void;
	onVulnerabilityFound?: (vuln: Vulnerability) => void;
	onProgress?: (completed: number, total: number) => void;
	onError?: (error: Error, attack?: AttackVector) => void;
}

const DEFAULT_CONFIG: BreachEngineConfig = {
	concurrency: 3,
	attackTimeout: 30000,
	delayBetweenAttacks: 100,
	stopOnBreach: false
};

/**
 * Main Breach Engine class
 */
export class BreachEngine {
	private config: BreachEngineConfig;
	private callbacks: BreachEngineCallbacks;
	private abortController: AbortController | null = null;
	private running = false;

	constructor(config: Partial<BreachEngineConfig> = {}, callbacks: BreachEngineCallbacks = {}) {
		this.config = { ...DEFAULT_CONFIG, ...config };
		this.callbacks = callbacks;
	}

	/**
	 * Run a breach test against a target project
	 */
	async run(
		attacks: AttackVector[],
		context: Omit<AttackContext, 'signal'>
	): Promise<BreachReport> {
		if (this.running) {
			throw new Error('Breach engine is already running');
		}

		this.running = true;
		this.abortController = new AbortController();

		const report = this.createEmptyReport(context);
		const filteredAttacks = this.filterAttacks(attacks);
		const startTime = Date.now();

		try {
			// Run attacks with controlled concurrency
			const results = await this.runAttacksWithConcurrency(
				filteredAttacks,
				context,
				report
			);

			// Process results
			for (const result of results) {
				report.results.push(result);
				this.updateStats(report, result);

				// Create vulnerability if breached
				if (result.breached) {
					const attack = attacks.find((a) => a.id === result.attackId);
					if (attack) {
						const vuln = this.createVulnerability(attack, result);
						report.vulnerabilities.push(vuln);
						this.callbacks.onVulnerabilityFound?.(vuln);
					}
				}
			}

			report.completedAt = new Date().toISOString();
			report.duration = Date.now() - startTime;

			return report;
		} finally {
			this.running = false;
			this.abortController = null;
		}
	}

	/**
	 * Stop the current breach test
	 */
	stop(): void {
		if (this.abortController) {
			this.abortController.abort();
		}
	}

	/**
	 * Check if engine is running
	 */
	isRunning(): boolean {
		return this.running;
	}

	/**
	 * Filter attacks based on config
	 */
	private filterAttacks(attacks: AttackVector[]): AttackVector[] {
		let filtered = [...attacks];

		// Filter by category
		if (this.config.categories?.length) {
			filtered = filtered.filter((a) => this.config.categories!.includes(a.category));
		}

		// Filter by severity
		if (this.config.minSeverity) {
			const minScore = SEVERITY_LEVELS[this.config.minSeverity].score;
			filtered = filtered.filter((a) => SEVERITY_LEVELS[a.severity].score >= minScore);
		}

		return filtered;
	}

	/**
	 * Run attacks with controlled concurrency
	 */
	private async runAttacksWithConcurrency(
		attacks: AttackVector[],
		context: Omit<AttackContext, 'signal'>,
		report: BreachReport
	): Promise<AttackResult[]> {
		const results: AttackResult[] = [];
		const queue = [...attacks];
		let completed = 0;

		// Process queue with concurrency limit
		const runNext = async (): Promise<void> => {
			while (queue.length > 0) {
				// Check if aborted
				if (this.abortController?.signal.aborted) {
					break;
				}

				// Check if should stop on breach
				if (this.config.stopOnBreach && results.some((r) => r.breached)) {
					break;
				}

				const attack = queue.shift()!;
				this.callbacks.onAttackStart?.(attack);

				try {
					const result = await this.runSingleAttack(attack, context);
					results.push(result);
					this.callbacks.onAttackComplete?.(attack, result);
				} catch (err) {
					const errorResult = this.createErrorResult(attack, err);
					results.push(errorResult);
					this.callbacks.onError?.(err instanceof Error ? err : new Error(String(err)), attack);
				}

				completed++;
				this.callbacks.onProgress?.(completed, attacks.length);

				// Delay between attacks
				if (queue.length > 0 && this.config.delayBetweenAttacks > 0) {
					await this.delay(this.config.delayBetweenAttacks);
				}
			}
		};

		// Start concurrent workers
		const workers = Array(Math.min(this.config.concurrency, attacks.length))
			.fill(null)
			.map(() => runNext());

		await Promise.all(workers);

		return results;
	}

	/**
	 * Run a single attack
	 */
	private async runSingleAttack(
		attack: AttackVector,
		context: Omit<AttackContext, 'signal'>
	): Promise<AttackResult> {
		const startTime = Date.now();

		// Create timeout promise
		const timeoutPromise = new Promise<never>((_, reject) => {
			setTimeout(() => reject(new Error('Attack timeout')), this.config.attackTimeout);
		});

		try {
			// Run attack with timeout
			const result = await Promise.race([
				attack.execute({ ...context, signal: this.abortController?.signal }),
				timeoutPromise
			]);

			return {
				...result,
				attackId: attack.id,
				duration: Date.now() - startTime,
				timestamp: new Date().toISOString()
			};
		} catch (err) {
			return this.createErrorResult(attack, err, Date.now() - startTime);
		}
	}

	/**
	 * Create an empty breach report
	 */
	private createEmptyReport(context: Omit<AttackContext, 'signal'>): BreachReport {
		const byCategory = {} as BreachReport['byCategory'];
		const bySeverity = {} as BreachReport['bySeverity'];

		for (const cat of Object.keys(ATTACK_CATEGORIES) as AttackCategory[]) {
			byCategory[cat] = { total: 0, breached: 0, secure: 0 };
		}

		for (const sev of Object.keys(SEVERITY_LEVELS) as AttackSeverity[]) {
			bySeverity[sev] = { total: 0, breached: 0 };
		}

		return {
			id: `report-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			projectId: '',
			projectName: '',
			stats: {
				total: 0,
				breached: 0,
				secure: 0,
				error: 0,
				skipped: 0
			},
			byCategory,
			bySeverity,
			results: [],
			vulnerabilities: [],
			startedAt: new Date().toISOString()
		};
	}

	/**
	 * Update report stats with a result
	 */
	private updateStats(report: BreachReport, result: AttackResult): void {
		report.stats.total++;

		if (result.status === 'breached') {
			report.stats.breached++;
		} else if (result.status === 'secure') {
			report.stats.secure++;
		} else if (result.status === 'error') {
			report.stats.error++;
		} else if (result.status === 'skipped') {
			report.stats.skipped++;
		}
	}

	/**
	 * Create a vulnerability from a breached attack
	 */
	private createVulnerability(attack: AttackVector, result: AttackResult): Vulnerability {
		return {
			id: `vuln-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			attackId: attack.id,
			category: attack.category,
			severity: attack.severity,
			title: attack.name,
			description: attack.description,
			impact: this.getImpactDescription(attack),
			fix: {
				summary: `Fix the ${attack.category.toUpperCase()} vulnerability`,
				steps: this.getFixSteps(attack)
			},
			evidence: result.evidence,
			status: 'open',
			discoveredAt: result.timestamp
		};
	}

	/**
	 * Create error result
	 */
	private createErrorResult(
		attack: AttackVector,
		err: unknown,
		duration = 0
	): AttackResult {
		return {
			attackId: attack.id,
			status: 'error',
			breached: false,
			summary: `Attack failed: ${err instanceof Error ? err.message : String(err)}`,
			details: {
				error: err instanceof Error ? err.message : String(err)
			},
			timestamp: new Date().toISOString(),
			duration
		};
	}

	/**
	 * Get impact description for vulnerability
	 */
	private getImpactDescription(attack: AttackVector): string {
		const impacts: Record<AttackCategory, string> = {
			rls: 'Unauthorized access to database rows. Attackers can read, modify, or delete data they should not have access to.',
			auth: 'Authentication bypass allows attackers to impersonate users or access protected resources without credentials.',
			storage: 'Unauthorized file access. Attackers can read, upload, or delete files in storage buckets.',
			functions: 'Edge function vulnerabilities can lead to code execution, data leaks, or service abuse.',
			realtime: 'Realtime subscription vulnerabilities allow attackers to receive unauthorized data updates.',
			vibecoder: 'Common security mistakes in AI-generated code that attackers actively look for.'
		};
		return impacts[attack.category];
	}

	/**
	 * Get fix steps for vulnerability
	 */
	private getFixSteps(attack: AttackVector): string[] {
		const steps: Record<AttackCategory, string[]> = {
			rls: [
				'Review your RLS policies for the affected table',
				'Ensure policies check auth.uid() properly',
				'Add policies for all operations (SELECT, INSERT, UPDATE, DELETE)',
				'Test policies with different user contexts'
			],
			auth: [
				'Review authentication configuration',
				'Ensure JWT tokens are validated properly',
				'Check session handling and token expiration',
				'Implement proper password policies'
			],
			storage: [
				'Review bucket policies',
				'Ensure storage RLS is enabled',
				'Check file path validation',
				'Implement proper access controls'
			],
			functions: [
				'Review function authentication',
				'Validate all input parameters',
				'Implement rate limiting',
				'Check for injection vulnerabilities'
			],
			realtime: [
				'Review realtime channel policies',
				'Ensure RLS applies to subscriptions',
				'Check broadcast permissions',
				'Implement proper channel authorization'
			],
			vibecoder: [
				'Review AI-generated code carefully',
				'Check for hardcoded credentials',
				'Verify proper error handling',
				'Test edge cases and error conditions'
			]
		};
		return steps[attack.category];
	}

	/**
	 * Delay helper
	 */
	private delay(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}
}

/**
 * Create a default breach engine instance
 */
export function createBreachEngine(
	config?: Partial<BreachEngineConfig>,
	callbacks?: BreachEngineCallbacks
): BreachEngine {
	return new BreachEngine(config, callbacks);
}
