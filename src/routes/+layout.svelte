<script lang="ts">
	import '../app.css';
	import { page } from '$app/stores';
	import { getTotalAttackCount } from '$lib/engine/attacks';

	let { children } = $props();

	// Check if we're on the landing page
	let isLandingPage = $derived($page.url.pathname === '/');
</script>

<div class="min-h-screen flex flex-col">
	<!-- Header - Hidden on landing page for full-screen hero -->
	{#if !isLandingPage}
		<header class="border-b border-gray-800 bg-surface-800/90 backdrop-blur-sm sticky top-0 z-50">
			<div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
				<a href="/" class="flex items-center gap-2 group">
					<span class="text-2xl text-supa-400 font-bold">◈</span>
					<span class="font-bold text-xl tracking-tight">
						<span class="text-supa-400">Supa</span><span class="text-white group-hover:text-supa-300 transition-colors">Ralph</span>
					</span>
				</a>
				<nav class="flex items-center gap-6">
					<a
						href="/"
						class="transition-colors text-sm text-gray-400 hover:text-white"
					>
						Scanner
					</a>
					<a
						href="https://github.com/vibeforge1111/vibeship-supascanner"
						target="_blank"
						class="transition-colors text-sm text-gray-400 hover:text-white"
					>
						GitHub
					</a>
				</nav>
				<!-- Attack Count -->
				<div class="flex items-center gap-2 text-sm">
					<span class="text-supa-400 font-mono">{getTotalAttackCount()}</span>
					<span class="text-gray-500">attacks</span>
				</div>
			</div>
		</header>
	{/if}

	<!-- Main content -->
	<main class="flex-1">
		{@render children()}
	</main>

	<!-- Footer - Also hidden on landing page -->
	{#if !isLandingPage}
		<footer class="border-t border-gray-800 py-6 bg-surface-800">
			<div class="max-w-7xl mx-auto px-4">
				<div class="flex flex-col md:flex-row items-center justify-between gap-4">
					<div class="text-center md:text-left">
						<p class="text-sm text-gray-500"><span class="text-supa-400">Supa</span>Ralph - Active Penetration Testing for Supabase</p>
						<p class="text-xs mt-1 text-gray-600">Don't guess what's broken. <span class="text-breach-400">Break it and prove it.</span></p>
					</div>
					<div class="flex items-center gap-6 text-xs">
						<a href="/terms" class="text-gray-500 hover:text-supa-400 transition-colors">Terms of Service</a>
						<a href="/privacy" class="text-gray-500 hover:text-supa-400 transition-colors">Privacy Policy</a>
						<a href="https://github.com/vibeforge1111/vibeship-supascanner" target="_blank" class="text-gray-500 hover:text-white transition-colors">GitHub</a>
					</div>
				</div>
				<p class="text-xs mt-4 text-center text-gray-700">For authorized testing only. Only scan projects you own or have permission to test.</p>
			</div>
		</footer>
	{/if}
</div>
