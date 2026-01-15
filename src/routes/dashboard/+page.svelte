<script lang="ts">
	import { projectStore } from '$lib/stores/project.svelte';
	import { ATTACK_CATEGORIES, SEVERITY_LEVELS, type AttackCategory, type BreachReport } from '$lib/types/attacks';
	import { BreachEngine } from '$lib/engine/breach-engine';
	import { ALL_ATTACKS } from '$lib/engine/attacks';

	// Engine state
	let running = $state(false);
	let progress = $state({ completed: 0, total: 0 });
	let currentAttack = $state<string | null>(null);
	let report = $state<BreachReport | null>(null);
	let error = $state<string | null>(null);

	// Category filter
	let selectedCategories = $state<AttackCategory[]>([]);

	// Toggle category selection
	function toggleCategory(cat: AttackCategory) {
		if (selectedCategories.includes(cat)) {
			selectedCategories = selectedCategories.filter((c) => c !== cat);
		} else {
			selectedCategories = [...selectedCategories, cat];
		}
	}

	// Start breach test
	async function startBreachTest() {
		const project = projectStore.activeProject;
		if (!project) {
			error = 'No project selected. Go to Settings to connect a project.';
			return;
		}

		running = true;
		error = null;
		report = null;
		progress = { completed: 0, total: ALL_ATTACKS.length };

		const engine = new BreachEngine(
			{
				concurrency: 3,
				attackTimeout: 15000,
				categories: selectedCategories.length > 0 ? selectedCategories : undefined
			},
			{
				onAttackStart: (attack) => {
					currentAttack = attack.name;
				},
				onAttackComplete: () => {
					progress = { ...progress, completed: progress.completed + 1 };
				},
				onProgress: (completed, total) => {
					progress = { completed, total };
				},
				onError: (err) => {
					console.error('Attack error:', err);
				}
			}
		);

		try {
			const result = await engine.run(ALL_ATTACKS, {
				targetUrl: project.url,
				anonKey: project.anonKey,
				serviceKey: project.serviceKey
			});

			result.projectId = project.id;
			result.projectName = project.name;
			report = result;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Breach test failed';
		} finally {
			running = false;
			currentAttack = null;
		}
	}

	// Get category stats from report
	function getCategoryStats(cat: AttackCategory) {
		if (!report) return { total: 0, breached: 0, secure: 0 };
		return report.byCategory[cat] || { total: 0, breached: 0, secure: 0 };
	}
</script>

<svelte:head>
	<title>Dashboard - SupaShield</title>
</svelte:head>

<div class="max-w-6xl mx-auto px-4 py-8">
	<!-- Header -->
	<div class="flex items-center justify-between mb-8">
		<div>
			<h1 class="text-2xl font-bold">Breach Dashboard</h1>
			<p class="text-gray-400 text-sm mt-1">
				{#if projectStore.activeProject}
					Testing: <span class="text-breach-400">{projectStore.activeProject.name}</span>
				{:else}
					No project selected
				{/if}
			</p>
		</div>

		<button
			onclick={startBreachTest}
			disabled={running || !projectStore.activeProject}
			class="btn-danger btn-lg"
		>
			{running ? 'Testing...' : '🔴 Run Breach Test'}
		</button>
	</div>

	<!-- Progress Bar -->
	{#if running}
		<div class="card mb-8">
			<div class="flex items-center justify-between mb-2">
				<span class="text-sm font-medium">
					{currentAttack || 'Initializing...'}
				</span>
				<span class="text-sm text-gray-400">
					{progress.completed}/{progress.total}
				</span>
			</div>
			<div class="w-full bg-gray-800 h-2">
				<div
					class="bg-breach-500 h-2 transition-all duration-300"
					style="width: {(progress.completed / progress.total) * 100}%"
				></div>
			</div>
		</div>
	{/if}

	<!-- Error Message -->
	{#if error}
		<div class="card-breach mb-8">
			<h3 class="font-bold text-breach-400 mb-2">Error</h3>
			<p class="text-sm text-gray-400">{error}</p>
		</div>
	{/if}

	<!-- Results Summary -->
	{#if report}
		<div class="grid grid-cols-4 gap-4 mb-8">
			<div class="card text-center">
				<div class="text-3xl font-bold">{report.stats.total}</div>
				<div class="text-sm text-gray-400">Total Tests</div>
			</div>
			<div class="card text-center">
				<div class="text-3xl font-bold text-breach-400">{report.stats.breached}</div>
				<div class="text-sm text-gray-400">Vulnerabilities</div>
			</div>
			<div class="card text-center">
				<div class="text-3xl font-bold text-secure-400">{report.stats.secure}</div>
				<div class="text-sm text-gray-400">Secure</div>
			</div>
			<div class="card text-center">
				<div class="text-3xl font-bold text-gray-400">{report.stats.error}</div>
				<div class="text-sm text-gray-400">Errors</div>
			</div>
		</div>
	{/if}

	<!-- Attack Categories Grid -->
	<div class="mb-8">
		<h2 class="text-lg font-bold mb-4">Attack Categories</h2>
		<p class="text-sm text-gray-400 mb-4">
			Click to filter. Leave all unchecked to test all categories.
		</p>
		<div class="grid grid-cols-2 md:grid-cols-3 gap-4">
			{#each Object.entries(ATTACK_CATEGORIES) as [key, cat]}
				{@const stats = getCategoryStats(key as AttackCategory)}
				{@const isSelected = selectedCategories.includes(key as AttackCategory)}
				<button
					onclick={() => toggleCategory(key as AttackCategory)}
					class="attack-category {isSelected ? 'selected' : ''} {stats.breached > 0 ? 'breached' : stats.total > 0 ? 'secure' : ''}"
				>
					<div class="text-2xl mb-2">{cat.icon}</div>
					<div class="font-bold">{cat.name}</div>
					<div class="text-xs text-gray-500 mb-2">{cat.description}</div>
					{#if report}
						<div class="flex justify-center gap-2 text-xs">
							{#if stats.breached > 0}
								<span class="text-breach-400">{stats.breached} breached</span>
							{/if}
							{#if stats.secure > 0}
								<span class="text-secure-400">{stats.secure} secure</span>
							{/if}
						</div>
					{/if}
				</button>
			{/each}
		</div>
	</div>

	<!-- Vulnerabilities List -->
	{#if report && report.vulnerabilities.length > 0}
		<div class="mb-8">
			<h2 class="text-lg font-bold mb-4 text-breach-400">
				🚨 {report.vulnerabilities.length} Vulnerabilities Found
			</h2>
			<div class="space-y-4">
				{#each report.vulnerabilities as vuln}
					<div class="card-breach">
						<div class="flex items-start justify-between">
							<div>
								<div class="flex items-center gap-2 mb-2">
									<span class="badge-{vuln.severity}">{vuln.severity.toUpperCase()}</span>
									<span class="text-sm text-gray-500">{ATTACK_CATEGORIES[vuln.category].name}</span>
								</div>
								<h3 class="font-bold mb-1">{vuln.title}</h3>
								<p class="text-sm text-gray-400">{vuln.description}</p>
							</div>
						</div>
						<div class="mt-4 pt-4 border-t border-gray-800">
							<h4 class="text-sm font-medium text-secure-400 mb-2">Fix Recommendation</h4>
							<p class="text-sm text-gray-400">{vuln.fix.summary}</p>
							{#if vuln.fix.steps}
								<ul class="mt-2 space-y-1">
									{#each vuln.fix.steps as step}
										<li class="text-xs text-gray-500">• {step}</li>
									{/each}
								</ul>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</div>
	{/if}

	<!-- No Project Warning -->
	{#if !projectStore.activeProject}
		<div class="card text-center py-12">
			<div class="text-4xl mb-4">🔗</div>
			<h3 class="font-bold mb-2">Connect a Project First</h3>
			<p class="text-gray-400 text-sm mb-4">
				Add your Supabase project credentials to start testing
			</p>
			<a href="/settings" class="btn-primary">
				Go to Settings →
			</a>
		</div>
	{/if}
</div>

<style>
	.btn-danger {
		@apply bg-breach-600 text-white px-6 py-3 font-bold hover:bg-breach-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed;
	}

	.btn-lg {
		@apply text-lg;
	}

	.btn-primary {
		@apply bg-breach-500 text-black px-4 py-2 font-medium hover:bg-breach-400 transition-colors;
	}

	.card {
		@apply bg-gray-900 border border-gray-800 p-4;
	}

	.card-breach {
		@apply bg-gray-900 border-l-4 border-l-breach-500 border-y border-r border-gray-800 p-4;
	}

	.attack-category {
		@apply p-4 text-center border border-gray-800 transition-all cursor-pointer hover:border-gray-600;
	}

	.attack-category.selected {
		@apply border-breach-500 bg-breach-500/10;
	}

	.attack-category.breached {
		@apply border-l-4 border-l-breach-500;
	}

	.attack-category.secure {
		@apply border-l-4 border-l-secure-500;
	}

	.badge-critical {
		@apply bg-breach-500/20 text-breach-400 text-xs px-2 py-0.5 font-mono;
	}

	.badge-high {
		@apply bg-breach-400/20 text-breach-300 text-xs px-2 py-0.5 font-mono;
	}

	.badge-medium {
		@apply bg-yellow-500/20 text-yellow-400 text-xs px-2 py-0.5 font-mono;
	}

	.badge-low {
		@apply bg-blue-500/20 text-blue-400 text-xs px-2 py-0.5 font-mono;
	}

	.badge-info {
		@apply bg-gray-500/20 text-gray-400 text-xs px-2 py-0.5 font-mono;
	}
</style>
