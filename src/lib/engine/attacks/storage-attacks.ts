/**
 * Storage Attacks
 * Tests for Supabase Storage bucket vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Storage Attack Vectors
 */
export const storageAttacks: AttackVector[] = [
	{
		id: 'storage-public-bucket-list',
		name: 'Public Bucket Enumeration',
		description: 'Attempts to list files in common bucket names',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'bucket', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const buckets = ['public', 'avatars', 'uploads', 'images', 'files', 'documents', 'media'];
			const accessibleBuckets: Record<string, unknown[]> = {};

			for (const bucket of buckets) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/list/${bucket}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const files = await response.json();
						if (Array.isArray(files) && files.length > 0) {
							accessibleBuckets[bucket] = files.slice(0, 10);
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = Object.keys(accessibleBuckets).length > 0;

			return {
				attackId: 'storage-public-bucket-list',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Found ${Object.keys(accessibleBuckets).length} buckets with listable files`
					: 'No buckets with public listing found',
				details: {},
				evidence: breached ? accessibleBuckets : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-path-traversal',
		name: 'Path Traversal',
		description: 'Tests for path traversal vulnerabilities in storage',
		category: 'storage',
		severity: 'critical',
		tags: ['storage', 'path-traversal', 'lfi'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const traversalPaths = [
				'../../../etc/passwd',
				'..%2F..%2F..%2Fetc%2Fpasswd',
				'....//....//....//etc/passwd',
				'public/../private/secret.txt'
			];

			const vulnerable: string[] = [];

			for (const path of traversalPaths) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/public/${path}`,
						{ method: 'HEAD' }
					);

					// If we get anything other than 400/404, might be vulnerable
					if (response.status !== 400 && response.status !== 404) {
						vulnerable.push(path);
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'storage-path-traversal',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? 'Potential path traversal vulnerability detected'
					: 'Path traversal attempts blocked',
				details: {},
				evidence: breached ? { vulnerablePaths: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-upload-any-type',
		name: 'Unrestricted File Upload',
		description: 'Tests if dangerous file types can be uploaded',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'upload', 'file-type'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const dangerousTypes = [
				{ name: 'test.html', type: 'text/html', content: '<script>alert(1)</script>' },
				{ name: 'test.svg', type: 'image/svg+xml', content: '<svg onload="alert(1)"/>' },
				{ name: 'test.php', type: 'application/x-php', content: '<?php echo 1; ?>' }
			];

			const uploaded: string[] = [];

			for (const file of dangerousTypes) {
				try {
					const formData = new FormData();
					const blob = new Blob([file.content], { type: file.type });
					formData.append('file', blob, file.name);

					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/public/${file.name}`,
						{
							method: 'POST',
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							},
							body: formData
						}
					);

					if (response.ok || response.status === 200) {
						uploaded.push(file.name);
						// Clean up
						await fetch(
							`${ctx.targetUrl}/storage/v1/object/public/${file.name}`,
							{
								method: 'DELETE',
								headers: {
									apikey: ctx.serviceKey,
									Authorization: `Bearer ${ctx.serviceKey}`
								}
							}
						);
					}
				} catch {
					// Continue
				}
			}

			const breached = uploaded.length > 0;

			return {
				attackId: 'storage-upload-any-type',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Dangerous file types accepted: ${uploaded.join(', ')}`
					: 'Dangerous file types blocked',
				details: {},
				evidence: breached ? { uploadedTypes: uploaded } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-missing-rls',
		name: 'Storage Without RLS',
		description: 'Checks if storage policies are properly configured',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'rls', 'policy'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Try to access storage objects directly
			const testPaths = [
				'avatars/test.png',
				'uploads/private/secret.pdf',
				'documents/internal.doc'
			];

			const accessible: string[] = [];

			for (const path of testPaths) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/public/${path}`,
						{
							method: 'HEAD',
							headers: {
								apikey: ctx.anonKey
							}
						}
					);

					if (response.ok) {
						accessible.push(path);
					}
				} catch {
					// Continue
				}
			}

			const breached = accessible.length > 0;

			return {
				attackId: 'storage-missing-rls',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} storage paths accessible without authentication`
					: 'Storage paths properly protected',
				details: {},
				evidence: breached ? { accessiblePaths: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
