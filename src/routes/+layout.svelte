<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import { projectStore } from '$lib/stores/project.svelte';

	let { children } = $props();
</script>

<div class="min-h-screen flex flex-col">
	<!-- Header -->
	<header class="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
		<div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
			<a href="/" class="flex items-center gap-2">
				<span class="text-2xl">🛡️</span>
				<span class="font-bold text-xl tracking-tight">SupaShield</span>
			</a>
			<nav class="flex items-center gap-6">
				<a
					href="/dashboard"
					class="transition-colors text-sm {$page.url.pathname === '/dashboard'
						? 'text-breach-400'
						: 'text-gray-400 hover:text-white'}"
				>
					Dashboard
				</a>
				<a
					href="/attacks"
					class="transition-colors text-sm {$page.url.pathname === '/attacks'
						? 'text-breach-400'
						: 'text-gray-400 hover:text-white'}"
				>
					Attacks
				</a>
				<a
					href="/settings"
					class="transition-colors text-sm {$page.url.pathname === '/settings'
						? 'text-breach-400'
						: 'text-gray-400 hover:text-white'}"
				>
					Settings
				</a>
			</nav>
			<!-- Active Project Indicator -->
			<div class="flex items-center gap-3">
				{#if projectStore.activeProject}
					<div class="flex items-center gap-2 text-sm">
						<span class="w-2 h-2 bg-secure-500 rounded-full animate-pulse"></span>
						<span class="text-gray-400 truncate max-w-32">{projectStore.activeProject.name}</span>
					</div>
				{:else}
					<a href="/settings" class="text-sm text-breach-400 hover:text-breach-300">
						Connect Project →
					</a>
				{/if}
			</div>
		</div>
	</header>

	<!-- Main content -->
	<main class="flex-1">
		{@render children()}
	</main>

	<!-- Footer -->
	<footer class="border-t border-gray-800 py-4 text-center text-sm text-gray-500">
		<p>SupaShield - Active Penetration Testing for Supabase</p>
		<p class="text-xs mt-1">Don't guess what's broken. Break it and prove it.</p>
	</footer>
</div>
