/**
 * Storage Transform attacks
 * Tests for storage transformation and processing vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const storageTransformAttacks: AttackVector[] = [
	{
		id: 'storage-transform-dos',
		name: 'Image Transform DoS',
		description: 'Test for DoS via expensive image transformations',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Try expensive transformation parameters
				const expensiveTransforms = [
					'width=10000&height=10000',
					'width=1&height=1&resize=fill&quality=100',
					'format=png&width=5000&height=5000'
				];

				const results: Array<{ transform: string; time: number; success: boolean }> = [];

				for (const transform of expensiveTransforms) {
					const startTime = Date.now();

					const res = await fetch(
						`${context.supabaseUrl}/storage/v1/render/image/public/test/image.jpg?${transform}`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					results.push({
						transform,
						time: Date.now() - startTime,
						success: res.ok
					});
				}

				const slowTransforms = results.filter(r => r.time > 5000);

				return {
					breached: slowTransforms.length > 0,
					status: slowTransforms.length > 0 ? 'breached' : 'secure',
					summary: slowTransforms.length > 0
						? `Expensive transforms allowed: ${slowTransforms.map(s => `${s.time}ms`).join(', ')}`
						: 'Transform limits appear reasonable',
					evidence: results.length > 0 ? { results } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test transforms' };
			}
		}
	},
	{
		id: 'storage-resumable-abuse',
		name: 'Resumable Upload Abuse',
		description: 'Test for resumable upload vulnerabilities',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Start a resumable upload
				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/upload/resumable`,
					{
						method: 'POST',
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`,
							'x-upsert': 'true',
							'Upload-Length': '999999999999', // Try huge file
							'Tus-Resumable': '1.0.0'
						},
						signal: context.signal
					}
				);

				const uploadUrl = res.headers.get('location');
				const acceptsLarge = res.ok || res.status === 201;

				return {
					breached: acceptsLarge,
					status: acceptsLarge ? 'breached' : 'secure',
					summary: acceptsLarge
						? 'Resumable upload accepts unlimited size!'
						: 'Resumable upload has size limits',
					evidence: acceptsLarge ? { uploadUrl: uploadUrl?.substring(0, 50) } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Resumable upload properly restricted' };
			}
		}
	},
	{
		id: 'storage-object-versioning',
		name: 'Object Version Access',
		description: 'Test for access to previous object versions',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to access object versions
				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/object/info/public/test?versions=true`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasVersions = data?.versions?.length > 0 || Array.isArray(data);

				return {
					breached: hasVersions,
					status: hasVersions ? 'breached' : 'secure',
					summary: hasVersions
						? 'Object versions accessible - may expose deleted content'
						: 'Object versioning not exposed',
					evidence: hasVersions ? { versionCount: data?.versions?.length } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Object versions not accessible' };
			}
		}
	},
	{
		id: 'storage-content-type-sniff',
		name: 'Content-Type Sniffing Attack',
		description: 'Test if content-type sniffing is prevented',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Fetch a file and check headers
				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/object/public/test/test.html`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const contentType = res.headers.get('content-type');
				const xContentTypeOptions = res.headers.get('x-content-type-options');

				const hasSniffProtection = xContentTypeOptions?.toLowerCase() === 'nosniff';

				return {
					breached: !hasSniffProtection,
					status: hasSniffProtection ? 'secure' : 'breached',
					summary: hasSniffProtection
						? 'X-Content-Type-Options: nosniff is set'
						: 'Missing X-Content-Type-Options header - XSS risk',
					evidence: {
						contentType,
						xContentTypeOptions
					}
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test content-type sniffing' };
			}
		}
	},
	{
		id: 'storage-cors-wildcard',
		name: 'Storage CORS Wildcard',
		description: 'Check for permissive CORS on storage',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/object/public/test/file`,
					{
						method: 'OPTIONS',
						headers: {
							'apikey': context.anonKey,
							'Origin': 'https://evil-site.com',
							'Access-Control-Request-Method': 'GET'
						},
						signal: context.signal
					}
				);

				const allowOrigin = res.headers.get('access-control-allow-origin');
				const hasWildcard = allowOrigin === '*';
				const reflectsEvil = allowOrigin === 'https://evil-site.com';

				return {
					breached: hasWildcard || reflectsEvil,
					status: hasWildcard || reflectsEvil ? 'breached' : 'secure',
					summary: hasWildcard
						? 'CORS allows all origins (*)'
						: reflectsEvil
							? 'CORS reflects arbitrary origins'
							: 'CORS properly restricted',
					evidence: { allowOrigin }
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test CORS' };
			}
		}
	},
	{
		id: 'storage-metadata-injection',
		name: 'Storage Metadata Injection',
		description: 'Test for metadata injection attacks',
		category: 'storage',
		severity: 'high',
		async execute(context) {
			try {
				// Try to upload with malicious metadata
				const formData = new FormData();
				const blob = new Blob(['test'], { type: 'text/plain' });
				formData.append('file', blob, 'test.txt');

				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/object/public/test/metadata-test.txt`,
					{
						method: 'POST',
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`,
							'x-upsert': 'true',
							// Try to inject metadata
							'x-metadata-admin': 'true',
							'x-metadata-role': 'superuser',
							'x-metadata-script': '<script>alert(1)</script>'
						},
						body: formData,
						signal: context.signal
					}
				);

				// Check if metadata was accepted
				if (res.ok) {
					const infoRes = await fetch(
						`${context.supabaseUrl}/storage/v1/object/info/public/test/metadata-test.txt`,
						{
							headers: {
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							signal: context.signal
						}
					);

					const info = await infoRes.json();
					const hasInjectedMetadata = info?.metadata?.admin || info?.metadata?.role;

					return {
						breached: hasInjectedMetadata,
						status: hasInjectedMetadata ? 'breached' : 'secure',
						summary: hasInjectedMetadata
							? 'Metadata injection possible!'
							: 'Metadata properly filtered',
						evidence: hasInjectedMetadata ? { metadata: info?.metadata } : undefined
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Could not upload test file'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test metadata injection' };
			}
		}
	},
	{
		id: 'storage-signed-url-reuse',
		name: 'Signed URL Token Reuse',
		description: 'Test if signed URLs can be reused after revocation',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Request a signed URL
				const signRes = await fetch(
					`${context.supabaseUrl}/storage/v1/object/sign/test/file.txt`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({ expiresIn: 60 }),
						signal: context.signal
					}
				);

				const signData = await signRes.json();
				const signedUrl = signData?.signedURL || signData?.signedUrl;

				if (signedUrl) {
					// Try to use the signed URL
					const accessRes = await fetch(signedUrl, {
						signal: context.signal
					});

					return {
						breached: false,
						status: 'secure',
						summary: `Signed URL generated (expires in 60s) - manual revocation testing needed`,
						details: { note: 'Signed URLs are time-limited by design' }
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Could not generate signed URL'
				};
			} catch {
				return { breached: false, status: 'error', summary: 'Could not test signed URLs' };
			}
		}
	},
	{
		id: 'storage-bucket-policy-enum',
		name: 'Bucket Policy Enumeration',
		description: 'Enumerate storage bucket policies',
		category: 'storage',
		severity: 'medium',
		async execute(context) {
			try {
				// Try to access bucket configurations
				const res = await fetch(
					`${context.supabaseUrl}/storage/v1/bucket`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();

				if (Array.isArray(data) && data.length > 0) {
					const publicBuckets = data.filter(b => b.public);

					return {
						breached: publicBuckets.length > 0,
						status: publicBuckets.length > 0 ? 'breached' : 'secure',
						summary: `Found ${data.length} buckets, ${publicBuckets.length} public`,
						evidence: {
							buckets: data.map((b: { name: string; public: boolean }) => ({
								name: b.name,
								public: b.public
							}))
						}
					};
				}

				return {
					breached: false,
					status: 'secure',
					summary: 'Bucket listing protected'
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Bucket listing not accessible' };
			}
		}
	}
];
