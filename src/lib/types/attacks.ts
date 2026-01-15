/**
 * SupaShield Attack Types
 * Defines the structure of attacks, results, and vulnerabilities
 */

export type AttackCategory =
	| 'rls'        // Row Level Security bypass
	| 'auth'       // Authentication bypass
	| 'storage'    // Storage/bucket attacks
	| 'functions'  // Edge Functions attacks
	| 'realtime'   // Realtime subscription attacks
	| 'vibecoder'  // Common AI/vibe-coder mistakes
	| 'api'        // API/PostgREST attacks
	| 'database';  // Database-level attacks

export type AttackSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AttackStatus = 'pending' | 'running' | 'breached' | 'secure' | 'error' | 'skipped';

export interface AttackVector {
	id: string;
	name: string;
	description: string;
	category: AttackCategory;
	severity: AttackSeverity;
	tags: string[];
	// The actual attack function
	execute: (context: AttackContext) => Promise<AttackResult>;
}

export interface AttackContext {
	// Target Supabase project
	targetUrl: string;
	anonKey: string;
	serviceKey: string;
	// Optional: specific table/bucket/function to target
	target?: string;
	// Optional: test data to use
	testData?: Record<string, unknown>;
	// Abort signal for cancellation
	signal?: AbortSignal;
}

export interface AttackResult {
	attackId: string;
	status: AttackStatus;
	// Whether the attack succeeded (vulnerability found)
	breached: boolean;
	// Human-readable summary
	summary: string;
	// Technical details of the attack
	details: {
		request?: {
			method: string;
			url: string;
			headers?: Record<string, string>;
			body?: unknown;
		};
		response?: {
			status: number;
			statusText: string;
			headers?: Record<string, string>;
			body?: unknown;
		};
		error?: string;
	};
	// Evidence of the breach (data leaked, actions performed)
	evidence?: unknown;
	// Timestamp
	timestamp: string;
	// Duration in ms
	duration: number;
}

export interface Vulnerability {
	id: string;
	attackId: string;
	category: AttackCategory;
	severity: AttackSeverity;
	title: string;
	description: string;
	impact: string;
	// The fix recommendation
	fix: {
		summary: string;
		code?: string;
		steps?: string[];
	};
	// Evidence from the attack
	evidence: unknown;
	// Status
	status: 'open' | 'fixed' | 'accepted' | 'false_positive';
	// Timestamps
	discoveredAt: string;
	fixedAt?: string;
}

export interface BreachReport {
	id: string;
	projectId: string;
	projectName: string;
	// Summary stats
	stats: {
		total: number;
		breached: number;
		secure: number;
		error: number;
		skipped: number;
	};
	// By category
	byCategory: Record<AttackCategory, {
		total: number;
		breached: number;
		secure: number;
	}>;
	// By severity
	bySeverity: Record<AttackSeverity, {
		total: number;
		breached: number;
	}>;
	// All results
	results: AttackResult[];
	// Discovered vulnerabilities
	vulnerabilities: Vulnerability[];
	// Timestamps
	startedAt: string;
	completedAt?: string;
	duration?: number;
}

export interface AttackPlaybook {
	id: string;
	name: string;
	description: string;
	attacks: AttackVector[];
	// Filter attacks
	categories?: AttackCategory[];
	severities?: AttackSeverity[];
	tags?: string[];
}

// Category metadata
export const ATTACK_CATEGORIES: Record<AttackCategory, {
	name: string;
	icon: string;
	description: string;
}> = {
	rls: {
		name: 'RLS Bypass',
		icon: '📊',
		description: 'Row Level Security policy bypass attacks'
	},
	auth: {
		name: 'Auth Bypass',
		icon: '🔐',
		description: 'Authentication and session attacks'
	},
	storage: {
		name: 'Storage',
		icon: '📁',
		description: 'Bucket and file access attacks'
	},
	functions: {
		name: 'Edge Functions',
		icon: '⚡',
		description: 'Serverless function attacks'
	},
	realtime: {
		name: 'Realtime',
		icon: '📡',
		description: 'Realtime subscription attacks'
	},
	vibecoder: {
		name: 'Vibe-Coder',
		icon: '🤖',
		description: 'Common AI-generated code mistakes'
	},
	api: {
		name: 'API/PostgREST',
		icon: '🔌',
		description: 'REST API and PostgREST exploitation attacks'
	},
	database: {
		name: 'Database',
		icon: '🗄️',
		description: 'PostgreSQL and database-level attacks'
	}
};

// Severity metadata
export const SEVERITY_LEVELS: Record<AttackSeverity, {
	name: string;
	color: string;
	score: number;
}> = {
	critical: { name: 'Critical', color: 'breach-500', score: 10 },
	high: { name: 'High', color: 'breach-400', score: 8 },
	medium: { name: 'Medium', color: 'yellow-500', score: 5 },
	low: { name: 'Low', color: 'blue-500', score: 2 },
	info: { name: 'Info', color: 'gray-500', score: 1 }
};
