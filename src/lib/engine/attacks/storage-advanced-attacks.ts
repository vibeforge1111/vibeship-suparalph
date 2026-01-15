/**
 * Advanced Storage Attacks
 * Tests for advanced Supabase Storage vulnerabilities
 */

import type { AttackVector, AttackContext, AttackResult } from '$lib/types/attacks';

/**
 * Advanced Storage Attack Vectors
 */
export const storageAdvancedAttacks: AttackVector[] = [
	{
		id: 'storage-signed-url-expiry',
		name: 'Signed URL Long Expiry',
		description: 'Tests if signed URLs have excessively long expiry times',
		category: 'storage',
		severity: 'medium',
		tags: ['storage', 'signed-url', 'expiry'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Check storage configuration for signed URL expiry
			const buckets = ['avatars', 'uploads', 'public', 'private', 'documents'];
			const longExpiry: Array<{ bucket: string; maxAge: number }> = [];

			for (const bucket of buckets) {
				try {
					// Try to create a signed URL via RPC if available
					const response = await fetch(`${ctx.targetUrl}/storage/v1/object/sign/${bucket}/test`, {
						method: 'POST',
						headers: {
							apikey: ctx.serviceKey,
							Authorization: `Bearer ${ctx.serviceKey}`,
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({ expiresIn: 31536000 }) // Try 1 year
					});

					if (response.ok) {
						const data = await response.json();
						if (data.signedURL) {
							// Check URL expiry parameter
							const url = new URL(data.signedURL, ctx.targetUrl);
							const token = url.searchParams.get('token');
							if (token) {
								// Very long expiry accepted
								longExpiry.push({ bucket, maxAge: 31536000 });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = longExpiry.length > 0;

			return {
				attackId: 'storage-signed-url-expiry',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${longExpiry.length} buckets allow very long signed URL expiry`
					: 'Signed URL expiry properly limited',
				details: {},
				evidence: breached ? { buckets: longExpiry } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-metadata-leak',
		name: 'Storage Metadata Leakage',
		description: 'Tests if file metadata exposes sensitive information',
		category: 'storage',
		severity: 'medium',
		tags: ['storage', 'metadata', 'information-disclosure'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const buckets = ['avatars', 'uploads', 'public', 'files'];
			const metadataLeaks: Array<{ bucket: string; files: number; fields: string[] }> = [];

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
						const data = await response.json();
						if (Array.isArray(data) && data.length > 0) {
							// Check what metadata fields are exposed
							const fields = Object.keys(data[0]).filter(k =>
								['owner', 'created_by', 'user_id', 'metadata', 'owner_id'].includes(k)
							);
							if (fields.length > 0) {
								metadataLeaks.push({ bucket, files: data.length, fields });
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = metadataLeaks.length > 0;

			return {
				attackId: 'storage-metadata-leak',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${metadataLeaks.length} buckets expose file metadata`
					: 'File metadata properly protected',
				details: {},
				evidence: breached ? { leaks: metadataLeaks } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-file-overwrite',
		name: 'Unauthorized File Overwrite',
		description: 'Tests if files can be overwritten without proper authorization',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'overwrite', 'integrity'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const buckets = ['avatars', 'uploads', 'public'];
			const vulnerable: string[] = [];

			for (const bucket of buckets) {
				try {
					// First, list files to find an existing one
					const listResponse = await fetch(
						`${ctx.targetUrl}/storage/v1/object/list/${bucket}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (listResponse.ok) {
						const files = await listResponse.json();
						if (Array.isArray(files) && files.length > 0) {
							const targetFile = files[0].name;

							// Try to overwrite with upsert
							const overwriteResponse = await fetch(
								`${ctx.targetUrl}/storage/v1/object/${bucket}/${targetFile}`,
								{
									method: 'POST',
									headers: {
										apikey: ctx.anonKey,
										Authorization: `Bearer ${ctx.anonKey}`,
										'Content-Type': 'text/plain',
										'x-upsert': 'true'
									},
									body: 'supashield_overwrite_test'
								}
							);

							if (overwriteResponse.ok) {
								vulnerable.push(bucket);
							}
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = vulnerable.length > 0;

			return {
				attackId: 'storage-file-overwrite',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `Files can be overwritten in ${vulnerable.length} buckets!`
					: 'File overwrite properly restricted',
				details: {},
				evidence: breached ? { buckets: vulnerable } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-directory-listing',
		name: 'Directory Listing Enabled',
		description: 'Tests if storage directories can be listed without authorization',
		category: 'storage',
		severity: 'medium',
		tags: ['storage', 'directory', 'enumeration'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const paths = ['', 'uploads', 'private', 'users', 'data'];
			const exposed: Array<{ path: string; fileCount: number }> = [];

			for (const path of paths) {
				try {
					const response = await fetch(
						`${ctx.targetUrl}/storage/v1/object/list/public${path ? '/' + path : ''}`,
						{
							headers: {
								apikey: ctx.anonKey,
								Authorization: `Bearer ${ctx.anonKey}`
							}
						}
					);

					if (response.ok) {
						const data = await response.json();
						if (Array.isArray(data) && data.length > 0) {
							exposed.push({ path: path || '/', fileCount: data.length });
						}
					}
				} catch {
					// Continue
				}
			}

			const breached = exposed.length > 0;

			return {
				attackId: 'storage-directory-listing',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${exposed.length} directories can be listed`
					: 'Directory listing properly restricted',
				details: {},
				evidence: breached ? { directories: exposed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-mime-bypass',
		name: 'MIME Type Restriction Bypass',
		description: 'Tests if MIME type restrictions can be bypassed',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'mime', 'bypass'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const buckets = ['avatars', 'uploads', 'public'];
			const bypassed: Array<{ bucket: string; technique: string }> = [];

			const bypassTechniques = [
				{ contentType: 'image/png', filename: 'test.php.png', technique: 'double extension' },
				{ contentType: 'image/png', filename: 'test.svg', technique: 'svg as image' },
				{ contentType: 'application/octet-stream', filename: 'test.exe', technique: 'binary stream' }
			];

			for (const bucket of buckets) {
				for (const { contentType, filename, technique } of bypassTechniques) {
					try {
						const response = await fetch(
							`${ctx.targetUrl}/storage/v1/object/${bucket}/${filename}`,
							{
								method: 'POST',
								headers: {
									apikey: ctx.anonKey,
									Authorization: `Bearer ${ctx.anonKey}`,
									'Content-Type': contentType
								},
								body: 'test content'
							}
						);

						if (response.ok || response.status === 200) {
							bypassed.push({ bucket, technique });
							// Cleanup
							await fetch(
								`${ctx.targetUrl}/storage/v1/object/${bucket}/${filename}`,
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
			}

			const breached = bypassed.length > 0;

			return {
				attackId: 'storage-mime-bypass',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `MIME restrictions bypassed ${bypassed.length} times`
					: 'MIME type restrictions enforced',
				details: {},
				evidence: breached ? { bypasses: bypassed } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	},
	{
		id: 'storage-size-limit',
		name: 'File Size Limit Check',
		description: 'Tests if file size limits are properly enforced',
		category: 'storage',
		severity: 'medium',
		tags: ['storage', 'size', 'dos'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			// Check if extremely large Content-Length is rejected early
			try {
				const response = await fetch(
					`${ctx.targetUrl}/storage/v1/object/public/large_test_file`,
					{
						method: 'POST',
						headers: {
							apikey: ctx.anonKey,
							Authorization: `Bearer ${ctx.anonKey}`,
							'Content-Type': 'application/octet-stream',
							'Content-Length': '10737418240' // 10GB
						},
						body: 'small actual content'
					}
				);

				// If we don't get 413 or early rejection, size limits may not be enforced
				const enforced = response.status === 413 || response.status === 400;

				return {
					attackId: 'storage-size-limit',
					status: enforced ? 'secure' : 'breached',
					breached: !enforced,
					summary: enforced
						? 'File size limits properly enforced'
						: 'Large file uploads may not be restricted',
					details: { responseStatus: response.status },
					timestamp: new Date().toISOString(),
					duration: 0
				};
			} catch {
				return {
					attackId: 'storage-size-limit',
					status: 'secure',
					breached: false,
					summary: 'File size limits appear enforced',
					details: {},
					timestamp: new Date().toISOString(),
					duration: 0
				};
			}
		}
	},
	{
		id: 'storage-public-url-guessing',
		name: 'Public URL Guessing',
		description: 'Tests if private files can be accessed via guessable URLs',
		category: 'storage',
		severity: 'high',
		tags: ['storage', 'url', 'access-control'],
		execute: async (ctx: AttackContext): Promise<AttackResult> => {
			const commonPaths = [
				'avatars/default.png',
				'uploads/test.pdf',
				'documents/report.pdf',
				'images/logo.png',
				'files/data.json'
			];

			const accessible: string[] = [];
			const baseUrl = ctx.targetUrl.replace('/rest/v1', '');

			for (const path of commonPaths) {
				try {
					const response = await fetch(
						`${baseUrl}/storage/v1/object/public/${path}`,
						{ method: 'HEAD' }
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
				attackId: 'storage-public-url-guessing',
				status: breached ? 'breached' : 'secure',
				breached,
				summary: breached
					? `${accessible.length} files accessible via predictable URLs`
					: 'No files accessible via URL guessing',
				details: {},
				evidence: breached ? { files: accessible } : undefined,
				timestamp: new Date().toISOString(),
				duration: 0
			};
		}
	}
];
