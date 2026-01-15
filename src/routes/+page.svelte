<script lang="ts">
	import { goto } from '$app/navigation';

	let showContent = $state(false);
	let scanUrl = $state('');
	let anonKey = $state('');
	let isScanning = $state(false);
	let scanProgress = $state(0);
	let attacksFound = $state(0);
	let attacksCompleted = $state(0);
	let totalAttacks = $state(252);
	let currentAttack = $state('');
	let scanComplete = $state(false);
	let scanError = $state('');
	let recentBreaches = $state<{title: string; severity: string; category: string}[]>([]);

	// Animate in content after ralph appears
	$effect(() => {
		setTimeout(() => {
			showContent = true;
		}, 800);
	});

	// REAL breach test using Server-Sent Events
	async function startScan() {
		if (!scanUrl) return;

		isScanning = true;
		scanProgress = 0;
		attacksFound = 0;
		attacksCompleted = 0;
		currentAttack = 'Initializing Ralph Wiggum Loop...';
		scanComplete = false;
		scanError = '';
		recentBreaches = [];

		try {
			// Use SSE for real-time progress
			const eventSource = new EventSource(
				`/api/scan?targetUrl=${encodeURIComponent(scanUrl)}&anonKey=${encodeURIComponent(anonKey)}`
			);

			eventSource.addEventListener('scan_start', (e) => {
				const data = JSON.parse(e.data);
				totalAttacks = data.total;
				currentAttack = `Starting scan against ${data.targetUrl}...`;
			});

			eventSource.addEventListener('attack_start', (e) => {
				const data = JSON.parse(e.data);
				currentAttack = `${data.category.toUpperCase()}: ${data.name}`;
			});

			eventSource.addEventListener('attack_complete', (e) => {
				const data = JSON.parse(e.data);
				attacksCompleted = data.completed;
				scanProgress = data.progress;
				if (data.breached) {
					currentAttack = `🚨 BREACHED: ${data.name}`;
				}
			});

			eventSource.addEventListener('breach_found', (e) => {
				const data = JSON.parse(e.data);
				attacksFound = data.totalBreaches;
				recentBreaches = [...recentBreaches.slice(-4), {
					title: data.title,
					severity: data.severity,
					category: data.category
				}];
			});

			eventSource.addEventListener('progress', (e) => {
				const data = JSON.parse(e.data);
				scanProgress = data.percent;
				attacksCompleted = data.completed;
			});

			eventSource.addEventListener('scan_complete', (e) => {
				const data = JSON.parse(e.data);
				scanComplete = true;
				currentAttack = `Scan complete! Found ${data.vulnerabilities} vulnerabilities`;
				eventSource.close();

				// Redirect to dashboard after showing results
				setTimeout(() => {
					goto('/dashboard');
				}, 3000);
			});

			eventSource.addEventListener('error', (e) => {
				if (e.data) {
					const data = JSON.parse(e.data);
					scanError = data.message;
				}
				eventSource.close();
			});

			eventSource.onerror = () => {
				if (!scanComplete) {
					scanError = 'Connection lost. The scan may still be running.';
				}
				eventSource.close();
			};
		} catch (error) {
			scanError = error instanceof Error ? error.message : 'Failed to start scan';
			isScanning = false;
		}
	}

	// Reset scan state
	function resetScan() {
		isScanning = false;
		scanProgress = 0;
		attacksFound = 0;
		attacksCompleted = 0;
		currentAttack = '';
		scanComplete = false;
		scanError = '';
		recentBreaches = [];
	}
</script>

<svelte:head>
	<title>SupaRalph - "I'm in danger!" - Supabase Penetration Testing</title>
	<meta name="description" content="AI-powered penetration testing for Supabase. Don't guess what's broken - break it and prove it with 252 attack vectors." />
</svelte:head>

<!-- Hero Section with Ralph Wiggum -->
<div class="relative min-h-screen bg-surface-900 overflow-hidden">
	<!-- Animated Background Grid - Supabase Green -->
	<div class="absolute inset-0 opacity-20">
		<div class="absolute inset-0" style="background-image: linear-gradient(rgba(62, 207, 142, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(62, 207, 142, 0.1) 1px, transparent 1px); background-size: 50px 50px;"></div>
	</div>

	<!-- ============================================== -->
	<!-- MOVIE-STYLE SECURITY LASER GRID               -->
	<!-- ============================================== -->

	<!-- DIAGONAL LASER BEAMS - Like heist movie security -->
	<!-- Green lasers from top-left to bottom-right -->
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 left-[10%] w-[1px] h-[200vh] bg-gradient-to-b from-supa-400/80 via-supa-400/40 to-transparent rotate-[30deg] origin-top animate-laser-beam-1 shadow-[0_0_10px_rgba(62,207,142,0.5)]"></div>
	</div>
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 left-[30%] w-[1px] h-[200vh] bg-gradient-to-b from-supa-400/60 via-supa-400/30 to-transparent rotate-[25deg] origin-top animate-laser-beam-2 shadow-[0_0_8px_rgba(62,207,142,0.4)]"></div>
	</div>
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 left-[50%] w-[1px] h-[200vh] bg-gradient-to-b from-supa-400/70 via-supa-400/35 to-transparent rotate-[20deg] origin-top animate-laser-beam-3 shadow-[0_0_10px_rgba(62,207,142,0.5)]"></div>
	</div>

	<!-- Red lasers from top-right to bottom-left -->
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 right-[10%] w-[1px] h-[200vh] bg-gradient-to-b from-breach-500/80 via-breach-500/40 to-transparent -rotate-[30deg] origin-top animate-laser-beam-4 shadow-[0_0_10px_rgba(239,68,68,0.5)]"></div>
	</div>
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 right-[30%] w-[1px] h-[200vh] bg-gradient-to-b from-breach-500/60 via-breach-500/30 to-transparent -rotate-[25deg] origin-top animate-laser-beam-5 shadow-[0_0_8px_rgba(239,68,68,0.4)]"></div>
	</div>
	<div class="absolute inset-0 pointer-events-none overflow-hidden">
		<div class="absolute top-0 right-[50%] w-[1px] h-[200vh] bg-gradient-to-b from-breach-500/70 via-breach-500/35 to-transparent -rotate-[20deg] origin-top animate-laser-beam-6 shadow-[0_0_10px_rgba(239,68,68,0.5)]"></div>
	</div>

	<!-- HORIZONTAL SWEEPING LASERS -->
	<div class="absolute top-[20%] left-0 w-full h-[1px] overflow-hidden">
		<div class="absolute w-[30%] h-full bg-gradient-to-r from-transparent via-supa-400 to-transparent animate-laser-sweep shadow-[0_0_15px_rgba(62,207,142,0.8)]"></div>
	</div>
	<div class="absolute top-[40%] left-0 w-full h-[1px] overflow-hidden">
		<div class="absolute w-[25%] h-full bg-gradient-to-r from-transparent via-breach-500 to-transparent animate-laser-sweep-reverse shadow-[0_0_15px_rgba(239,68,68,0.8)]"></div>
	</div>
	<div class="absolute top-[60%] left-0 w-full h-[1px] overflow-hidden">
		<div class="absolute w-[30%] h-full bg-gradient-to-r from-transparent via-supa-400 to-transparent animate-laser-sweep-slow shadow-[0_0_15px_rgba(62,207,142,0.8)]"></div>
	</div>
	<div class="absolute top-[80%] left-0 w-full h-[1px] overflow-hidden">
		<div class="absolute w-[20%] h-full bg-gradient-to-r from-transparent via-breach-500 to-transparent animate-laser-sweep-reverse-slow shadow-[0_0_15px_rgba(239,68,68,0.8)]"></div>
	</div>

	<!-- CROSSING X PATTERN - Classic security grid -->
	<div class="absolute inset-0 pointer-events-none overflow-hidden opacity-20">
		<div class="absolute top-0 left-0 w-full h-full">
			<div class="absolute w-[2px] h-[150%] bg-gradient-to-b from-transparent via-supa-400 to-transparent left-1/2 top-0 rotate-45 origin-top-left animate-pulse"></div>
			<div class="absolute w-[2px] h-[150%] bg-gradient-to-b from-transparent via-breach-500 to-transparent right-1/2 top-0 -rotate-45 origin-top-right animate-pulse" style="animation-delay: 0.5s;"></div>
		</div>
	</div>

	<!-- VERTICAL SCANNING BEAMS -->
	<div class="absolute top-0 left-[25%] h-full w-[1px] overflow-hidden">
		<div class="absolute w-full h-[20%] bg-gradient-to-b from-transparent via-supa-400/60 to-transparent animate-laser-vertical shadow-[0_0_12px_rgba(62,207,142,0.6)]"></div>
	</div>
	<div class="absolute top-0 right-[25%] h-full w-[1px] overflow-hidden">
		<div class="absolute w-full h-[20%] bg-gradient-to-b from-transparent via-breach-500/60 to-transparent animate-laser-vertical-reverse shadow-[0_0_12px_rgba(239,68,68,0.6)]"></div>
	</div>

	<!-- EDGE GLOW EFFECT -->
	<div class="absolute inset-0 pointer-events-none">
		<div class="absolute top-0 left-0 w-full h-32 bg-gradient-to-b from-supa-500/10 to-transparent"></div>
		<div class="absolute bottom-0 left-0 w-full h-32 bg-gradient-to-t from-breach-500/10 to-transparent"></div>
		<div class="absolute top-0 left-0 w-32 h-full bg-gradient-to-r from-supa-500/5 to-transparent"></div>
		<div class="absolute top-0 right-0 w-32 h-full bg-gradient-to-l from-breach-500/5 to-transparent"></div>
	</div>

	<!-- Main Hero Content -->
	<div class="relative z-10 flex flex-col items-center justify-center min-h-screen px-4">

		<!-- Ralph Wiggum Image with Effects -->
		<div class="relative mb-8">
			<!-- Title ABOVE the image -->
			<div class="absolute -top-32 left-1/2 -translate-x-1/2 text-center whitespace-nowrap z-20">
				<h1 class="text-4xl md:text-5xl font-bold tracking-tight">
					<span class="text-supa-400">Supa</span><span class="text-white">Ralph</span>
				</h1>
				<p class="text-xs md:text-sm text-gray-400 mt-1 font-mono">Supabase Penetration Testing</p>
			</div>

			<!-- Animated Laser Border Frame -->
			<div class="absolute -inset-4 border-2 border-breach-500 animate-danger-pulse"></div>
			<div class="absolute -inset-8 border border-supa-500/30 animate-danger-pulse" style="animation-delay: 0.5s;"></div>
			<div class="absolute -inset-12 border border-breach-500/20 animate-danger-pulse" style="animation-delay: 1s;"></div>

			<!-- Corner Laser Points -->
			<div class="absolute -top-4 -left-4 w-3 h-3 bg-supa-400 animate-pulse shadow-lg shadow-supa-400/50"></div>
			<div class="absolute -top-4 -right-4 w-3 h-3 bg-breach-500 animate-pulse shadow-lg shadow-breach-500/50" style="animation-delay: 0.25s;"></div>
			<div class="absolute -bottom-4 -left-4 w-3 h-3 bg-breach-500 animate-pulse shadow-lg shadow-breach-500/50" style="animation-delay: 0.5s;"></div>
			<div class="absolute -bottom-4 -right-4 w-3 h-3 bg-supa-400 animate-pulse shadow-lg shadow-supa-400/50" style="animation-delay: 0.75s;"></div>

			<!-- The Ralph -->
			<div class="relative group">
				<img
					src="/ralph-wiggum.avif"
					alt="Ralph Wiggum - I'm in danger!"
					class="w-64 h-64 md:w-80 md:h-80 object-cover shadow-2xl transition-transform duration-300 group-hover:scale-105"
				/>

				<!-- Glitch Overlay on Hover -->
				<div class="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity">
					<div class="absolute inset-0 bg-breach-500/20 mix-blend-overlay animate-glitch"></div>
				</div>

				<!-- Horizontal Scan Line -->
				<div class="absolute inset-0 overflow-hidden pointer-events-none">
					<div class="absolute w-full h-[2px] bg-gradient-to-r from-transparent via-supa-400 to-transparent animate-scan-line shadow-lg shadow-supa-400/50"></div>
				</div>

				<!-- Vertical Scan Line -->
				<div class="absolute inset-0 overflow-hidden pointer-events-none">
					<div class="absolute h-full w-[2px] bg-gradient-to-b from-transparent via-breach-500 to-transparent animate-scan-line-vertical shadow-lg shadow-breach-500/50"></div>
				</div>
			</div>

			<!-- "I'm in danger" Speech Bubble - NO ANIMATION -->
			<div class="absolute -top-4 -right-4 md:-right-8 bg-white text-black px-4 py-2 font-bold text-sm md:text-base shadow-lg transform rotate-3">
				<span class="text-breach-600">"I'm in danger!"</span>
				<div class="absolute -bottom-2 left-4 w-0 h-0 border-l-8 border-r-8 border-t-8 border-l-transparent border-r-transparent border-t-white"></div>
			</div>
		</div>

		<!-- Interactive Scan Form - MAIN FOCUS -->
		<div class="w-full max-w-2xl {showContent ? 'animate-slide-up' : 'opacity-0'}" style="animation-delay: 0.5s;">
			{#if !isScanning}
				<div class="relative">
					<!-- Danger Border Animation -->
					<div class="absolute -inset-0.5 bg-gradient-to-r from-breach-500 via-supa-500 to-breach-500 opacity-75 animate-pulse"></div>

					<div class="relative bg-surface-800 p-6">
						<div class="flex items-center gap-2 mb-2">
							<label class="block text-sm text-gray-400 font-mono">
								<span class="text-supa-400">$</span> Enter your Supabase URL to start penetration test
							</label>
							<!-- URL Help Tooltip -->
							<div class="relative group/help">
								<span class="text-gray-600 hover:text-supa-400 cursor-help text-xs">[?]</span>
								<div class="absolute bottom-full left-0 mb-2 w-72 p-3 bg-surface-900 border border-gray-700 text-xs text-gray-300 opacity-0 invisible group-hover/help:opacity-100 group-hover/help:visible transition-all z-50">
									<p class="font-bold text-supa-400 mb-2">Where to find your Supabase URL:</p>
									<ol class="list-decimal list-inside space-y-1 text-gray-400">
										<li>Go to <span class="text-white">supabase.com/dashboard</span></li>
										<li>Select your project</li>
										<li>Click <span class="text-white">Settings</span> → <span class="text-white">API</span></li>
										<li>Copy the <span class="text-white">Project URL</span></li>
									</ol>
									<p class="mt-2 text-gray-500">Format: https://xxxxx.supabase.co</p>
								</div>
							</div>
						</div>
						<div class="flex gap-3 mb-3">
							<input
								type="text"
								bind:value={scanUrl}
								placeholder="https://your-project.supabase.co"
								class="flex-1 bg-surface-900 border border-gray-700 px-4 py-3 text-white font-mono focus:border-supa-500 focus:outline-none transition-colors"
							/>
							<button
								onclick={startScan}
								disabled={!scanUrl}
								class="px-6 py-3 bg-breach-600 hover:bg-breach-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-bold transition-all hover:shadow-lg hover:shadow-breach-500/30"
							>
								BREACH TEST
							</button>
						</div>
						<!-- Optional API Key -->
						<details class="text-sm">
							<summary class="text-gray-500 cursor-pointer hover:text-gray-400 flex items-center gap-2">
								<span>+ Add anon key (optional, for deeper testing)</span>
								<!-- Anon Key Help Tooltip -->
								<div class="relative group/anonhelp inline-block">
									<span class="text-gray-600 hover:text-supa-400 cursor-help text-xs">[?]</span>
									<div class="absolute bottom-full left-0 mb-2 w-72 p-3 bg-surface-900 border border-gray-700 text-xs text-gray-300 opacity-0 invisible group-hover/anonhelp:opacity-100 group-hover/anonhelp:visible transition-all z-50">
										<p class="font-bold text-supa-400 mb-2">Where to find your anon key:</p>
										<ol class="list-decimal list-inside space-y-1 text-gray-400">
											<li>Go to <span class="text-white">supabase.com/dashboard</span></li>
											<li>Select your project</li>
											<li>Click <span class="text-white">Settings</span> → <span class="text-white">API</span></li>
											<li>Copy <span class="text-white">anon public</span> key</li>
										</ol>
										<p class="mt-2 text-gray-500">Starts with: eyJhbGciOiJIUzI1...</p>
										<p class="mt-1 text-yellow-500/80">This key is safe to use - it's public</p>
									</div>
								</div>
							</summary>
							<input
								type="text"
								bind:value={anonKey}
								placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
								class="w-full mt-2 bg-surface-900 border border-gray-700 px-4 py-2 text-white font-mono text-xs focus:border-supa-500 focus:outline-none"
							/>
						</details>
						<p class="text-xs text-gray-600 mt-3 font-mono">
							[!] Only test projects you own or have explicit authorization to test
						</p>
					</div>
				</div>
			{:else}
				<!-- REAL Scanning Progress -->
				<div class="bg-surface-800 border-2 border-breach-500 animate-danger-pulse p-6">
					<div class="flex items-center justify-between mb-4">
						<div class="flex items-center gap-4">
							<div class="w-4 h-4 bg-breach-500 animate-pulse"></div>
							<span class="text-breach-400 font-bold font-mono">
								{scanComplete ? '✓ SCAN COMPLETE' : 'RALPH WIGGUM LOOP ACTIVE'}
							</span>
						</div>
						{#if !scanComplete}
							<span class="text-xs text-gray-500 font-mono">
								{attacksCompleted}/{totalAttacks} attacks
							</span>
						{/if}
					</div>

					<!-- Progress Bar -->
					<div class="h-3 bg-surface-900 mb-4 overflow-hidden">
						<div
							class="h-full bg-gradient-to-r from-breach-500 via-breach-400 to-supa-500 transition-all duration-300 {scanComplete ? '' : 'animate-pulse'}"
							style="width: {scanProgress}%"
						></div>
					</div>

					<!-- Current Attack -->
					<div class="font-mono text-sm text-gray-400 mb-4 h-6 overflow-hidden">
						<span class="text-supa-400">›</span> {currentAttack}
					</div>

					<!-- Error Message -->
					{#if scanError}
						<div class="bg-breach-900/30 border border-breach-700 p-3 mb-4 text-sm text-breach-400">
							{scanError}
						</div>
					{/if}

					<!-- Live Stats -->
					<div class="flex gap-8 mb-4">
						<div class="text-center">
							<div class="text-3xl font-bold text-breach-400">{attacksFound}</div>
							<div class="text-xs text-gray-500 uppercase">Breaches Found</div>
						</div>
						<div class="text-center">
							<div class="text-3xl font-bold text-supa-400">{scanProgress}%</div>
							<div class="text-xs text-gray-500 uppercase">Complete</div>
						</div>
						<div class="text-center">
							<div class="text-3xl font-bold text-gray-400">{attacksCompleted}</div>
							<div class="text-xs text-gray-500 uppercase">Attacks Run</div>
						</div>
					</div>

					<!-- Recent Breaches (live feed) -->
					{#if recentBreaches.length > 0}
						<div class="border-t border-gray-700 pt-4">
							<div class="text-xs text-gray-500 uppercase mb-2">Recent Breaches</div>
							<div class="space-y-1">
								{#each recentBreaches as breach}
									<div class="flex items-center gap-2 text-sm font-mono">
										<span class="w-2 h-2 {breach.severity === 'critical' ? 'bg-breach-500' : breach.severity === 'high' ? 'bg-yellow-500' : 'bg-gray-500'}"></span>
										<span class="text-gray-500">[{breach.category}]</span>
										<span class="text-breach-400 truncate">{breach.title}</span>
									</div>
								{/each}
							</div>
						</div>
					{/if}

					<!-- Reset Button (when complete or error) -->
					{#if scanComplete || scanError}
						<button
							onclick={resetScan}
							class="mt-4 w-full py-2 border border-gray-600 text-gray-400 hover:text-white hover:border-supa-500 transition-colors text-sm"
						>
							Run Another Scan
						</button>
					{/if}
				</div>
			{/if}
		</div>

		<!-- Secondary Links -->
		<div class="flex gap-6 mt-6 text-sm {showContent ? 'animate-fade-in' : 'opacity-0'}" style="animation-delay: 0.7s;">
			<a href="/dashboard" class="text-gray-500 hover:text-supa-400 transition-colors">
				Dashboard
			</a>
			<a href="/attacks" class="text-gray-500 hover:text-supa-400 transition-colors">
				252 Attacks
			</a>
			<a href="https://github.com/vibeforge1111/vibeship-supascanner" target="_blank" class="text-gray-500 hover:text-white transition-colors">
				GitHub
			</a>
		</div>
	</div>
</div>

<!-- Attack Categories Section -->
<section class="bg-surface-800 py-20 px-4">
	<div class="max-w-6xl mx-auto">
		<h2 class="text-3xl font-bold text-center mb-4">
			<span class="text-supa-400">10</span> Attack Scenarios
		</h2>
		<p class="text-gray-400 text-center mb-12 max-w-2xl mx-auto">
			Comprehensive coverage of every Supabase attack surface. Each scenario contains multiple attack vectors tested against real vulnerabilities.
		</p>

		<div class="grid md:grid-cols-2 lg:grid-cols-5 gap-4">
			<!-- Scenario Cards -->
			{#each [
				{ num: '01', name: 'No Security', desc: 'RLS Disabled', icon: '--', color: 'breach' },
				{ num: '02', name: 'Bad RLS', desc: 'USING (true)', icon: '!!', color: 'breach' },
				{ num: '03', name: 'Business Logic', desc: 'Price & IDOR', icon: '$$', color: 'breach' },
				{ num: '04', name: 'Vibecoder', desc: 'AI Mistakes', icon: '<>', color: 'supa' },
				{ num: '05', name: 'Injection', desc: 'SQL & XSS', icon: ';--', color: 'breach' },
				{ num: '06', name: 'GraphQL/Vault', desc: 'Secrets', icon: '{}', color: 'breach' },
				{ num: '07', name: 'Auth/Tenant', desc: 'Multi-tenant', icon: '@', color: 'breach' },
				{ num: '08', name: 'Database', desc: 'Deep Access', icon: '[DB]', color: 'breach' },
				{ num: '09', name: 'AI/Realtime', desc: 'ML & WS', icon: '~/', color: 'supa' },
				{ num: '10', name: 'Backup/Logs', desc: 'Operations', icon: '>>', color: 'breach' },
			] as scenario}
				<div class="group bg-surface-900 border border-gray-800 hover:border-{scenario.color}-500 p-4 transition-all hover:shadow-lg hover:shadow-{scenario.color}-500/20 cursor-pointer">
					<div class="flex items-start justify-between mb-2">
						<span class="text-lg font-mono text-gray-500 group-hover:text-{scenario.color}-400 transition-colors">{scenario.icon}</span>
						<span class="text-xs font-mono text-gray-600 group-hover:text-{scenario.color}-400">{scenario.num}</span>
					</div>
					<h3 class="font-bold text-white group-hover:text-{scenario.color}-400 transition-colors">{scenario.name}</h3>
					<p class="text-xs text-gray-500">{scenario.desc}</p>
				</div>
			{/each}
		</div>
	</div>
</section>

<!-- Features Section -->
<section class="bg-surface-900 py-20 px-4">
	<div class="max-w-6xl mx-auto">
		<div class="grid md:grid-cols-3 gap-8">
			<!-- Feature 1 -->
			<div class="bg-surface-800 border border-gray-800 p-6 group hover:border-breach-500 transition-all">
				<div class="w-12 h-12 bg-breach-500/20 flex items-center justify-center mb-4 group-hover:bg-breach-500/30 transition-colors">
					<span class="text-xl text-breach-400">●</span>
				</div>
				<h3 class="text-xl font-bold mb-2 text-white">Active Breach Testing</h3>
				<p class="text-gray-400 text-sm">
					Actually attempts to exploit your Supabase using 252 attack vectors.
					No guessing - real proof of vulnerabilities.
				</p>
			</div>

			<!-- Feature 2 -->
			<div class="bg-surface-800 border border-gray-800 p-6 group hover:border-supa-500 transition-all">
				<div class="w-12 h-12 bg-supa-500/20 flex items-center justify-center mb-4 group-hover:bg-supa-500/30 transition-colors">
					<span class="text-xl text-supa-400">↻</span>
				</div>
				<h3 class="text-xl font-bold mb-2 text-white">Ralph Wiggum Loop</h3>
				<p class="text-gray-400 text-sm">
					"I'm in danger!" - Persistent iteration until every vulnerability is found.
					Keeps attacking until the attack surface is fully mapped.
				</p>
			</div>

			<!-- Feature 3 -->
			<div class="bg-surface-800 border border-gray-800 p-6 group hover:border-supa-500 transition-all">
				<div class="w-12 h-12 bg-supa-500/20 flex items-center justify-center mb-4 group-hover:bg-supa-500/30 transition-colors">
					<span class="text-xl text-supa-400">✓</span>
				</div>
				<h3 class="text-xl font-bold mb-2 text-white">Fix Verification</h3>
				<p class="text-gray-400 text-sm">
					After you apply fixes, re-runs all attacks to confirm they're actually resolved.
					No more "trust me, it's fixed."
				</p>
			</div>
		</div>
	</div>
</section>

<!-- Terminal Section -->
<section class="bg-surface-800 py-20 px-4">
	<div class="max-w-4xl mx-auto">
		<div class="bg-surface-900 border border-gray-800 overflow-hidden">
			<!-- Terminal Header -->
			<div class="bg-surface-700 px-4 py-2 flex items-center gap-2 border-b border-gray-800">
				<div class="w-3 h-3 bg-breach-500"></div>
				<div class="w-3 h-3 bg-yellow-500"></div>
				<div class="w-3 h-3 bg-supa-500"></div>
				<span class="ml-4 text-gray-400 text-sm font-mono">suparalph-scanner</span>
			</div>

			<!-- Terminal Content -->
			<div class="p-6 font-mono text-sm space-y-2">
				<p><span class="text-supa-400">$</span> suparalph scan https://your-project.supabase.co</p>
				<p class="text-gray-500">Initializing SupaRalph v1.0.0...</p>
				<p class="text-gray-500">Loading 252 attack vectors...</p>
				<p class="text-yellow-400">&gt; Starting breach test...</p>
				<p>&nbsp;</p>
				<p class="text-breach-400">× BREACHED Scenario 1: RLS Bypass - Got 3 users with SSN</p>
				<p class="text-breach-400">× BREACHED Scenario 2: Bad RLS - Read 3 profiles</p>
				<p class="text-breach-400">× BREACHED Scenario 4: Vibecoder - Found default credentials!</p>
				<p class="text-breach-400">× BREACHED Scenario 7: Auth - 4 OAuth secrets exposed!</p>
				<p class="text-breach-400">× BREACHED Scenario 9: AI - Conversations from 6 users visible!</p>
				<p>&nbsp;</p>
				<p class="text-white">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</p>
				<p class="text-breach-400 font-bold">[!] CRITICAL: 49 vulnerabilities found</p>
				<p class="text-gray-400">Detection Rate: <span class="text-supa-400">100%</span> | Time: 12.4s</p>
				<p>&nbsp;</p>
				<p><span class="text-supa-400">$</span> <span class="border-r-2 border-supa-400 animate-blink pr-1"></span></p>
			</div>
		</div>
	</div>
</section>

<!-- Warning Section -->
<section class="bg-breach-900/30 border-y border-breach-800 py-12 px-4">
	<div class="max-w-4xl mx-auto text-center">
		<h3 class="text-2xl font-bold text-breach-400 mb-4">[!] For Educational & Authorized Testing Only</h3>
		<p class="text-gray-400">
			Only test projects you own or have explicit permission to test.
			SupaRalph performs real attacks that could affect data.
			<span class="text-breach-400">Use responsibly.</span>
		</p>
	</div>
</section>

<!-- Final CTA -->
<section class="bg-surface-900 py-20 px-4">
	<div class="max-w-4xl mx-auto text-center">
		<h2 class="text-4xl font-bold mb-4">
			Ready to find out if you're <span class="text-breach-400">"in danger"</span>?
		</h2>
		<p class="text-gray-400 mb-8">
			Start your penetration test now and discover vulnerabilities before attackers do.
		</p>
		<div class="flex justify-center gap-4">
			<a href="/settings" class="px-8 py-4 bg-supa-600 hover:bg-supa-500 text-white font-bold text-lg transition-all hover:shadow-xl hover:shadow-supa-500/30">
				Connect Your Project →
			</a>
			<a href="https://github.com/vibeforge1111/vibeship-supascanner" target="_blank" class="px-8 py-4 border border-gray-600 hover:border-white text-gray-300 hover:text-white transition-all">
				View on GitHub
			</a>
		</div>
	</div>
</section>

<!-- Landing Page Footer -->
<footer class="bg-surface-800 border-t border-gray-800 py-8 px-4">
	<div class="max-w-6xl mx-auto">
		<div class="flex flex-col md:flex-row items-center justify-between gap-6">
			<!-- Brand -->
			<div class="flex items-center gap-2">
				<span class="text-2xl text-supa-400 font-bold">◈</span>
				<span class="font-bold text-xl tracking-tight">
					<span class="text-supa-400">Supa</span><span class="text-white">Ralph</span>
				</span>
			</div>

			<!-- Links -->
			<div class="flex flex-wrap items-center justify-center gap-6 text-sm">
				<a href="/terms" class="text-gray-400 hover:text-supa-400 transition-colors">Terms of Service</a>
				<a href="/privacy" class="text-gray-400 hover:text-supa-400 transition-colors">Privacy Policy</a>
				<a href="/dashboard" class="text-gray-400 hover:text-supa-400 transition-colors">Dashboard</a>
				<a href="/attacks" class="text-gray-400 hover:text-supa-400 transition-colors">252 Attacks</a>
				<a href="https://github.com/vibeforge1111/vibeship-supascanner" target="_blank" class="text-gray-400 hover:text-white transition-colors">GitHub</a>
			</div>
		</div>

		<!-- Bottom -->
		<div class="mt-8 pt-6 border-t border-gray-800 text-center">
			<p class="text-xs text-gray-600">
				SupaRalph is a security testing tool. Use responsibly and only on systems you own or have permission to test.
			</p>
			<p class="text-xs text-gray-700 mt-2">
				By using this tool, you agree to our <a href="/terms" class="text-supa-500 hover:text-supa-400">Terms of Service</a> and <a href="/privacy" class="text-supa-500 hover:text-supa-400">Privacy Policy</a>.
			</p>
		</div>
	</div>
</footer>
