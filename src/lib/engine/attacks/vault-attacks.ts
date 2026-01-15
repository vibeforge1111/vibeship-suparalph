/**
 * Supabase Vault attacks
 * Tests for secret management vulnerabilities
 */

import type { AttackVector } from '$lib/types/attacks';

export const vaultAttacks: AttackVector[] = [
	{
		id: 'vault-secrets-enumeration',
		name: 'Vault Secrets Enumeration',
		description: 'Attempt to enumerate secrets stored in Supabase Vault',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to access vault.secrets table
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/vault.secrets?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && !data.error;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? `Vault secrets accessible - found ${data.length} secrets!`
						: 'Vault secrets properly protected',
					evidence: hasAccess ? { secretCount: data.length } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Vault not accessible' };
			}
		}
	},
	{
		id: 'vault-decrypted-secrets',
		name: 'Vault Decrypted Secrets Access',
		description: 'Try to access decrypted secrets via vault.decrypted_secrets view',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/vault.decrypted_secrets?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && data.length > 0;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? `CRITICAL: Decrypted secrets exposed - ${data.length} secrets!`
						: 'Decrypted secrets view protected',
					evidence: hasAccess ? { secrets: data.map((s: { name: string }) => s.name) } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Decrypted secrets not accessible' };
			}
		}
	},
	{
		id: 'vault-key-exposure',
		name: 'Vault Encryption Key Exposure',
		description: 'Check if vault encryption keys are exposed',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				// Try to access pgsodium key table
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/pgsodium.key?select=*`,
					{
						headers: {
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						signal: context.signal
					}
				);

				const data = await res.json();
				const hasAccess = Array.isArray(data) && !data.error;

				return {
					breached: hasAccess,
					status: hasAccess ? 'breached' : 'secure',
					summary: hasAccess
						? 'CRITICAL: pgsodium encryption keys exposed!'
						: 'Encryption keys properly protected',
					evidence: hasAccess ? { keyCount: data.length } : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'pgsodium keys not accessible' };
			}
		}
	},
	{
		id: 'vault-create-secret',
		name: 'Vault Unauthorized Secret Creation',
		description: 'Attempt to create secrets in vault without authorization',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			try {
				const res = await fetch(
					`${context.supabaseUrl}/rest/v1/rpc/vault.create_secret`,
					{
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
							'apikey': context.anonKey,
							'Authorization': `Bearer ${context.anonKey}`
						},
						body: JSON.stringify({
							new_secret: 'test-attack-value',
							new_name: 'supashield-test-secret'
						}),
						signal: context.signal
					}
				);

				const data = await res.json();
				const created = res.ok && !data.error;

				return {
					breached: created,
					status: created ? 'breached' : 'secure',
					summary: created
						? 'Can create vault secrets without authorization!'
						: 'Vault secret creation properly restricted',
					evidence: created ? data : undefined
				};
			} catch {
				return { breached: false, status: 'secure', summary: 'Cannot create vault secrets' };
			}
		}
	},
	{
		id: 'vault-rpc-functions',
		name: 'Vault RPC Functions Exposed',
		description: 'Check if vault management functions are callable',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			const vaultFunctions = [
				'vault.create_secret',
				'vault.update_secret',
				'vault.secrets_lookup'
			];

			const exposed: string[] = [];

			for (const func of vaultFunctions) {
				try {
					const res = await fetch(
						`${context.supabaseUrl}/rest/v1/rpc/${func}`,
						{
							method: 'POST',
							headers: {
								'Content-Type': 'application/json',
								'apikey': context.anonKey,
								'Authorization': `Bearer ${context.anonKey}`
							},
							body: JSON.stringify({}),
							signal: context.signal
						}
					);

					// If we don't get a 404, the function exists
					if (res.status !== 404) {
						exposed.push(func);
					}
				} catch {
					// Function not accessible
				}
			}

			return {
				breached: exposed.length > 0,
				status: exposed.length > 0 ? 'breached' : 'secure',
				summary: exposed.length > 0
					? `Vault functions exposed: ${exposed.join(', ')}`
					: 'Vault functions properly restricted',
				evidence: exposed.length > 0 ? { functions: exposed } : undefined
			};
		}
	}
];
