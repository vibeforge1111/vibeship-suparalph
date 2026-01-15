<script lang="ts">
	import { goto } from '$app/navigation';
</script>

<svelte:head>
	<title>SupaShield - AI-Powered Supabase Penetration Testing</title>
</svelte:head>

<div class="max-w-4xl mx-auto px-4 py-16">
	<!-- Hero Section -->
	<div class="text-center mb-16">
		<div class="text-6xl mb-6">🛡️</div>
		<h1 class="text-4xl font-bold mb-4">SupaShield</h1>
		<p class="text-xl text-gray-400 mb-2">AI-Powered Supabase Penetration Testing</p>
		<p class="text-gray-500 max-w-2xl mx-auto">
			Don't tell vibe coders what <em>might</em> be broken.
			<span class="text-breach-400 font-semibold">Show them what IS broken by breaking it.</span>
		</p>
	</div>

	<!-- CTA -->
	<div class="flex justify-center gap-4 mb-16">
		<a href="/settings" class="btn-primary">
			Connect Your Project →
		</a>
		<a href="/dashboard" class="btn-secondary">
			View Demo
		</a>
	</div>

	<!-- Features Grid -->
	<div class="grid md:grid-cols-3 gap-6 mb-16">
		<div class="card">
			<div class="text-2xl mb-3">🔴</div>
			<h3 class="font-bold mb-2">Active Breach Testing</h3>
			<p class="text-sm text-gray-400">
				Actually attempts to exploit your Supabase using 100+ attack vectors.
				No guessing - real proof of vulnerabilities.
			</p>
		</div>

		<div class="card">
			<div class="text-2xl mb-3">🔄</div>
			<h3 class="font-bold mb-2">Ralph Wiggum Loop</h3>
			<p class="text-sm text-gray-400">
				Persistent iteration until every vulnerability is found.
				Keeps attacking until the attack surface is fully mapped.
			</p>
		</div>

		<div class="card">
			<div class="text-2xl mb-3">✅</div>
			<h3 class="font-bold mb-2">Fix Verification</h3>
			<p class="text-sm text-gray-400">
				After you apply fixes, re-runs all attacks to confirm they're actually resolved.
				No more "trust me, it's fixed."
			</p>
		</div>
	</div>

	<!-- Attack Categories -->
	<div class="mb-16">
		<h2 class="text-xl font-bold mb-6 text-center">6 Attack Categories</h2>
		<div class="grid grid-cols-2 md:grid-cols-3 gap-4">
			<div class="attack-category">
				<div class="text-lg mb-1">📊</div>
				<div class="font-semibold text-sm">RLS Bypass</div>
				<div class="text-xs text-gray-500">Table access attacks</div>
			</div>
			<div class="attack-category">
				<div class="text-lg mb-1">🔐</div>
				<div class="font-semibold text-sm">Auth Bypass</div>
				<div class="text-xs text-gray-500">Session & JWT attacks</div>
			</div>
			<div class="attack-category">
				<div class="text-lg mb-1">📁</div>
				<div class="font-semibold text-sm">Storage</div>
				<div class="text-xs text-gray-500">Bucket & file attacks</div>
			</div>
			<div class="attack-category">
				<div class="text-lg mb-1">⚡</div>
				<div class="font-semibold text-sm">Edge Functions</div>
				<div class="text-xs text-gray-500">Serverless attacks</div>
			</div>
			<div class="attack-category">
				<div class="text-lg mb-1">📡</div>
				<div class="font-semibold text-sm">Realtime</div>
				<div class="text-xs text-gray-500">Subscription attacks</div>
			</div>
			<div class="attack-category">
				<div class="text-lg mb-1">🤖</div>
				<div class="font-semibold text-sm">Vibe-Coder</div>
				<div class="text-xs text-gray-500">AI mistake patterns</div>
			</div>
		</div>
	</div>

	<!-- Danger Zone Warning -->
	<div class="card-breach">
		<h3 class="font-bold text-breach-400 mb-2">⚠️ For Educational & Authorized Testing Only</h3>
		<p class="text-sm text-gray-400">
			Only test projects you own or have explicit permission to test.
			SupaShield performs real attacks that could affect data.
		</p>
	</div>
</div>
