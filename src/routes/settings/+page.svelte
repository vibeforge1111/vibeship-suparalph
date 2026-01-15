<script lang="ts">
	import {
		projectStore,
		addProject,
		updateProject,
		deleteProject,
		setActiveProject,
		validateSupabaseUrl,
		validateApiKey,
		testConnection,
		type TargetProject
	} from '$lib/stores/project.svelte';

	// Form state
	let name = $state('');
	let url = $state('');
	let anonKey = $state('');
	let serviceKey = $state('');

	// UI state
	let showAddForm = $state(false);
	let editingProject = $state<TargetProject | null>(null);
	let testing = $state(false);
	let testResult = $state<{ success: boolean; error?: string } | null>(null);
	let formError = $state<string | null>(null);

	// Validation
	const urlValid = $derived(url.length === 0 || validateSupabaseUrl(url));
	const anonKeyValid = $derived(anonKey.length === 0 || validateApiKey(anonKey));
	const serviceKeyValid = $derived(serviceKey.length === 0 || validateApiKey(serviceKey));
	const formValid = $derived(
		name.length > 0 && validateSupabaseUrl(url) && validateApiKey(anonKey) && validateApiKey(serviceKey)
	);

	function resetForm() {
		name = '';
		url = '';
		anonKey = '';
		serviceKey = '';
		testResult = null;
		formError = null;
	}

	function openAddForm() {
		resetForm();
		editingProject = null;
		showAddForm = true;
	}

	function openEditForm(project: TargetProject) {
		name = project.name;
		url = project.url;
		anonKey = project.anonKey;
		serviceKey = project.serviceKey;
		editingProject = project;
		showAddForm = true;
		testResult = null;
		formError = null;
	}

	function closeForm() {
		showAddForm = false;
		editingProject = null;
		resetForm();
	}

	async function handleTestConnection() {
		if (!validateSupabaseUrl(url) || !validateApiKey(anonKey)) {
			testResult = { success: false, error: 'Invalid URL or API key format' };
			return;
		}

		testing = true;
		testResult = null;

		try {
			testResult = await testConnection(url, anonKey);
		} finally {
			testing = false;
		}
	}

	function handleSubmit() {
		if (!formValid) return;

		formError = null;

		try {
			if (editingProject) {
				updateProject(editingProject.id, { name, url, anonKey, serviceKey });
			} else {
				addProject(name, url, anonKey, serviceKey);
			}
			closeForm();
		} catch (err) {
			formError = err instanceof Error ? err.message : 'Failed to save project';
		}
	}

	function handleDelete(project: TargetProject) {
		if (confirm(`Delete "${project.name}"? This cannot be undone.`)) {
			deleteProject(project.id);
		}
	}

	function handleSelect(project: TargetProject) {
		setActiveProject(project.id);
	}
</script>

<svelte:head>
	<title>Settings - SupaRalph</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-4 py-8">
	<!-- Header -->
	<div class="flex items-center justify-between mb-8">
		<div>
			<h1 class="text-2xl font-bold">Target Projects</h1>
			<p class="text-gray-400 text-sm mt-1">
				Configure Supabase projects to test for vulnerabilities
			</p>
		</div>
		<button onclick={openAddForm} class="btn-primary">
			+ Add Project
		</button>
	</div>

	<!-- Warning Banner -->
	<div class="card-breach mb-8">
		<h3 class="font-bold text-breach-400 mb-2">Security Notice</h3>
		<p class="text-sm text-gray-400">
			Your credentials are stored locally in your browser. Never share your service role key.
			Only test projects you own or have explicit permission to test.
		</p>
	</div>

	<!-- Projects List -->
	{#if projectStore.projects.length === 0}
		<div class="card text-center py-12">
			<div class="text-4xl mb-4">🎯</div>
			<h3 class="font-bold mb-2">No Projects Yet</h3>
			<p class="text-gray-400 text-sm mb-4">
				Add a Supabase project to start penetration testing
			</p>
			<button onclick={openAddForm} class="btn-primary">
				Connect Your First Project
			</button>
		</div>
	{:else}
		<div class="space-y-4">
			{#each projectStore.projects as project}
				<div
					class="card hover:border-breach-500/30 transition-colors cursor-pointer {project.id === projectStore.activeProjectId ? 'border-breach-500' : ''}"
					onclick={() => handleSelect(project)}
					role="button"
					tabindex="0"
					onkeypress={(e) => e.key === 'Enter' && handleSelect(project)}
				>
					<div class="flex items-start justify-between">
						<div class="flex-1">
							<div class="flex items-center gap-3 mb-2">
								{#if project.id === projectStore.activeProjectId}
									<span class="badge-success">ACTIVE</span>
								{/if}
								<h3 class="font-bold">{project.name}</h3>
							</div>
							<p class="text-sm text-gray-400 font-mono truncate">{project.url}</p>
							<div class="flex gap-4 mt-2 text-xs text-gray-500">
								<span>Added: {new Date(project.createdAt).toLocaleDateString()}</span>
								{#if project.lastTested}
									<span>Last tested: {new Date(project.lastTested).toLocaleDateString()}</span>
								{/if}
							</div>
						</div>
						<div class="flex gap-2">
							<button
								class="btn-ghost btn-sm"
								onclick={(e) => { e.stopPropagation(); openEditForm(project); }}
							>
								Edit
							</button>
							<button
								class="btn-ghost btn-sm text-breach-400 hover:text-breach-300"
								onclick={(e) => { e.stopPropagation(); handleDelete(project); }}
							>
								Delete
							</button>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}

	<!-- Add/Edit Form Modal -->
	{#if showAddForm}
		<div class="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
			<div class="card max-w-lg w-full max-h-[90vh] overflow-y-auto">
				<div class="flex items-center justify-between mb-6">
					<h2 class="text-xl font-bold">
						{editingProject ? 'Edit Project' : 'Add New Project'}
					</h2>
					<button onclick={closeForm} class="text-gray-400 hover:text-white text-xl">
						&times;
					</button>
				</div>

				<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-4">
					<!-- Project Name -->
					<div>
						<label for="name" class="block text-sm font-medium mb-2">Project Name</label>
						<input
							type="text"
							id="name"
							bind:value={name}
							placeholder="My Supabase App"
							class="input"
							required
						/>
					</div>

					<!-- Supabase URL -->
					<div>
						<label for="url" class="block text-sm font-medium mb-2">Supabase Project URL</label>
						<input
							type="url"
							id="url"
							bind:value={url}
							placeholder="https://your-project.supabase.co"
							class="input {!urlValid ? 'border-breach-500' : ''}"
							required
						/>
						{#if !urlValid}
							<p class="text-breach-400 text-xs mt-1">Must be a valid Supabase URL (https://...supabase.co)</p>
						{/if}
					</div>

					<!-- Anon Key -->
					<div>
						<label for="anonKey" class="block text-sm font-medium mb-2">
							Anon (Public) Key
							<span class="text-gray-500 font-normal ml-2">Used to simulate anonymous attackers</span>
						</label>
						<textarea
							id="anonKey"
							bind:value={anonKey}
							placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
							rows="3"
							class="input font-mono text-xs {!anonKeyValid ? 'border-breach-500' : ''}"
							required
						></textarea>
						{#if !anonKeyValid && anonKey.length > 0}
							<p class="text-breach-400 text-xs mt-1">Invalid API key format</p>
						{/if}
					</div>

					<!-- Service Role Key -->
					<div>
						<label for="serviceKey" class="block text-sm font-medium mb-2">
							Service Role Key
							<span class="text-gray-500 font-normal ml-2">Used to verify RLS and get schema info</span>
						</label>
						<textarea
							id="serviceKey"
							bind:value={serviceKey}
							placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
							rows="3"
							class="input font-mono text-xs {!serviceKeyValid ? 'border-breach-500' : ''}"
							required
						></textarea>
						{#if !serviceKeyValid && serviceKey.length > 0}
							<p class="text-breach-400 text-xs mt-1">Invalid API key format</p>
						{/if}
						<p class="text-yellow-500/70 text-xs mt-2">
							Never share this key. It bypasses RLS and has full database access.
						</p>
					</div>

					<!-- Test Connection -->
					<div class="pt-2">
						<button
							type="button"
							onclick={handleTestConnection}
							disabled={!validateSupabaseUrl(url) || !validateApiKey(anonKey) || testing}
							class="btn-secondary btn-sm w-full"
						>
							{testing ? 'Testing...' : 'Test Connection'}
						</button>
						{#if testResult}
							<div class="mt-2 p-3 {testResult.success ? 'bg-green-500/10 text-green-400' : 'bg-breach-500/10 text-breach-400'} text-sm">
								{testResult.success ? '✓ Connection successful' : `✗ ${testResult.error}`}
							</div>
						{/if}
					</div>

					{#if formError}
						<div class="p-3 bg-breach-500/10 text-breach-400 text-sm">
							{formError}
						</div>
					{/if}

					<!-- Submit -->
					<div class="flex gap-3 pt-4">
						<button type="button" onclick={closeForm} class="btn-secondary flex-1">
							Cancel
						</button>
						<button type="submit" disabled={!formValid} class="btn-primary flex-1">
							{editingProject ? 'Save Changes' : 'Add Project'}
						</button>
					</div>
				</form>
			</div>
		</div>
	{/if}
</div>

<style>
	.btn-primary {
		@apply bg-breach-500 text-black px-4 py-2 font-medium hover:bg-breach-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed;
	}

	.btn-secondary {
		@apply border border-gray-600 text-gray-300 px-4 py-2 font-medium hover:border-gray-500 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed;
	}

	.btn-ghost {
		@apply text-gray-400 hover:text-white transition-colors;
	}

	.btn-sm {
		@apply px-3 py-1 text-sm;
	}

	.card {
		@apply bg-gray-900 border border-gray-700 p-6;
	}

	.card-breach {
		@apply bg-breach-500/5 border border-breach-500/30 p-4;
	}

	.input {
		@apply w-full bg-gray-950 border border-gray-700 px-4 py-2 text-white placeholder-gray-500 focus:border-breach-500 focus:outline-none transition-colors;
	}

	.badge-success {
		@apply bg-green-500/20 text-green-400 text-xs px-2 py-0.5 font-mono;
	}
</style>
