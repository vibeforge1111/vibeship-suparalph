<script lang="ts">
	import { page } from '$app/stores';
	import { projectStore } from '$lib/stores/project.svelte';

	const navItems = [
		{ href: '/', label: 'Home' },
		{ href: '/dashboard', label: 'Dashboard' },
		{ href: '/settings', label: 'Settings' }
	];
</script>

<nav class="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-40">
	<div class="max-w-6xl mx-auto px-4 py-3">
		<div class="flex items-center justify-between">
			<!-- Logo -->
			<a href="/" class="flex items-center gap-2 hover:opacity-80 transition-opacity">
				<span class="text-xl">🛡️</span>
				<span class="font-bold text-lg">SupaShield</span>
			</a>

			<!-- Nav Links -->
			<div class="flex items-center gap-6">
				{#each navItems as item}
					<a
						href={item.href}
						class="text-sm font-medium transition-colors {$page.url.pathname === item.href
							? 'text-breach-400'
							: 'text-gray-400 hover:text-white'}"
					>
						{item.label}
					</a>
				{/each}
			</div>

			<!-- Active Project Indicator -->
			<div class="flex items-center gap-3">
				{#if projectStore.activeProject}
					<div class="flex items-center gap-2 text-sm">
						<span class="w-2 h-2 bg-secure-500 rounded-full"></span>
						<span class="text-gray-400 truncate max-w-32">{projectStore.activeProject.name}</span>
					</div>
				{:else}
					<a href="/settings" class="text-sm text-breach-400 hover:text-breach-300">
						Connect Project →
					</a>
				{/if}
			</div>
		</div>
	</div>
</nav>
