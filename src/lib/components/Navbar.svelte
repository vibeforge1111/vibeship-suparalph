<script lang="ts">
	import { page } from '$app/stores';
	import { getTotalAttackCount } from '$lib/engine/attacks';
</script>

<nav class="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-40">
	<div class="max-w-6xl mx-auto px-4 py-3">
		<div class="flex items-center justify-between">
			<!-- Logo -->
			<a href="/" class="flex items-center gap-2 hover:opacity-80 transition-opacity">
				<span class="text-2xl text-supa-400 font-bold">◈</span>
				<span class="font-bold text-lg"><span class="text-supa-400">Supa</span><span class="text-white">Ralph</span></span>
			</a>

			<!-- Nav Links -->
			<div class="flex items-center gap-6">
				<a
					href="/"
					class="text-sm font-medium transition-colors {$page.url.pathname === '/'
						? 'text-breach-400'
						: 'text-gray-400 hover:text-white'}"
				>
					Scanner
				</a>
				<a
					href="https://github.com/vibeforge1111/vibeship-supascanner"
					target="_blank"
					class="text-sm font-medium text-gray-400 hover:text-white transition-colors"
				>
					GitHub
				</a>
			</div>

			<!-- Attack Count Badge -->
			<div class="flex items-center gap-2 text-sm">
				<span class="text-supa-400 font-mono">{getTotalAttackCount()}</span>
				<span class="text-gray-500">attacks</span>
			</div>
		</div>
	</div>
</nav>
