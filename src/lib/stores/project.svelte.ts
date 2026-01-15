/**
 * Project Store - Session-only storage for target Supabase project credentials
 * SECURITY: Credentials are NOT persisted to localStorage or any storage
 * They only exist in memory for the current browser session
 */

export interface TargetProject {
	id: string;
	name: string;
	url: string;
	anonKey: string;
	serviceKey: string;
	createdAt: string;
	lastTested?: string;
}

// In-memory only - no persistence
let projects = $state<TargetProject[]>([]);
let activeProjectId = $state<string | null>(null);

// Derived: active project
const activeProject = $derived(
	activeProjectId ? projects.find((p) => p.id === activeProjectId) ?? null : null
);

/**
 * Add a new target project (session only)
 */
export function addProject(
	name: string,
	url: string,
	anonKey: string,
	serviceKey: string
): TargetProject {
	const project: TargetProject = {
		id: `proj-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
		name,
		url: url.replace(/\/$/, ''), // Remove trailing slash
		anonKey,
		serviceKey,
		createdAt: new Date().toISOString()
	};

	projects = [...projects, project];

	// Auto-select if first project
	if (projects.length === 1) {
		setActiveProject(project.id);
	}

	return project;
}

/**
 * Update an existing project
 */
export function updateProject(
	id: string,
	updates: Partial<Omit<TargetProject, 'id' | 'createdAt'>>
): TargetProject | null {
	const index = projects.findIndex((p) => p.id === id);
	if (index === -1) return null;

	const updated = { ...projects[index], ...updates };
	projects = [...projects.slice(0, index), updated, ...projects.slice(index + 1)];

	return updated;
}

/**
 * Delete a project
 */
export function deleteProject(id: string): boolean {
	const index = projects.findIndex((p) => p.id === id);
	if (index === -1) return false;

	projects = [...projects.slice(0, index), ...projects.slice(index + 1)];

	// Clear active if deleted
	if (activeProjectId === id) {
		activeProjectId = projects.length > 0 ? projects[0].id : null;
	}

	return true;
}

/**
 * Set the active project
 */
export function setActiveProject(id: string | null): void {
	activeProjectId = id;
}

/**
 * Get all projects (reactive)
 */
export function getProjects(): TargetProject[] {
	return projects;
}

/**
 * Get active project (reactive)
 */
export function getActiveProject(): TargetProject | null {
	return activeProject;
}

/**
 * Validate Supabase URL format
 */
export function validateSupabaseUrl(url: string): boolean {
	try {
		const parsed = new URL(url);
		// Accept both http (local) and https (production)
		const isValidProtocol = parsed.protocol === 'https:' || parsed.protocol === 'http:';
		// Accept localhost, 127.0.0.1, or supabase domains
		const isValidHost =
			parsed.hostname.includes('supabase') ||
			parsed.hostname === 'localhost' ||
			parsed.hostname === '127.0.0.1' ||
			parsed.hostname.startsWith('192.168.') ||
			parsed.hostname.endsWith('.local');
		return isValidProtocol && isValidHost;
	} catch {
		return false;
	}
}

/**
 * Validate API key format (basic check)
 */
export function validateApiKey(key: string): boolean {
	// Accept both JWT tokens (eyJ...) and local dev keys (sb_publishable_*, sb_secret_*)
	const isJwtKey = key.length >= 100 && key.includes('.');
	const isLocalKey = key.startsWith('sb_publishable_') || key.startsWith('sb_secret_');
	return isJwtKey || isLocalKey;
}

/**
 * Test connection to a Supabase project
 */
export async function testConnection(
	url: string,
	anonKey: string
): Promise<{ success: boolean; error?: string }> {
	try {
		// Try to reach the Supabase health endpoint
		const response = await fetch(`${url}/rest/v1/`, {
			method: 'GET',
			headers: {
				apikey: anonKey,
				Authorization: `Bearer ${anonKey}`
			}
		});

		if (response.ok || response.status === 400) {
			// 400 is expected when no table specified
			return { success: true };
		}

		return { success: false, error: `HTTP ${response.status}: ${response.statusText}` };
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : 'Connection failed' };
	}
}

// Export reactive getters for use in components
export const projectStore = {
	get projects() {
		return projects;
	},
	get activeProject() {
		return activeProject;
	},
	get activeProjectId() {
		return activeProjectId;
	}
};
