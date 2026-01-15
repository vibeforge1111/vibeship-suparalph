/**
 * SupaRalph Attack Playbook
 * Complete collection of attack vectors for all categories
 */

import type { AttackVector } from '$lib/types/attacks';

// Core attacks
import { rlsAttacks } from './rls-attacks';
import { rlsAdvancedAttacks } from './rls-advanced-attacks';
import { authAttacks } from './auth-attacks';
import { authAdvancedAttacks } from './auth-advanced-attacks';
import { storageAttacks } from './storage-attacks';
import { storageAdvancedAttacks } from './storage-advanced-attacks';
import { functionsAttacks } from './functions-attacks';
import { realtimeAttacks } from './realtime-attacks';
import { vibecoderAttacks } from './vibecoder-attacks';
import { vibecoderAdvancedAttacks } from './vibecoder-advanced-attacks';
import { apiAttacks } from './api-attacks';
import { databaseAttacks } from './database-attacks';
import { infrastructureAttacks } from './infrastructure-attacks';
import { dataExposureAttacks } from './data-exposure-attacks';
import { injectionAttacks } from './injection-attacks';
import { businessLogicAttacks } from './business-logic-attacks';
import { dosAttacks } from './dos-attacks';

// NEW: Advanced attack modules
import { graphqlAttacks } from './graphql-attacks';
import { vaultAttacks } from './vault-attacks';
import { multiTenantAttacks } from './multi-tenant-attacks';
import { authEdgeAttacks } from './auth-edge-attacks';
import { postgrestAdvancedAttacks } from './postgrest-advanced-attacks';
import { scheduledJobAttacks } from './scheduled-job-attacks';
import { webhookAttacks } from './webhook-attacks';
import { extensionAttacks } from './extension-attacks';
import { realtimeAdvancedAttacks } from './realtime-advanced-attacks';
import { storageTransformAttacks } from './storage-transform-attacks';
import { managementApiAttacks } from './management-api-attacks';

// NEW: Deep attack modules (Round 2)
import { edgeFunctionsDeepAttacks } from './edge-functions-deep-attacks';
import { authProviderAttacks } from './auth-provider-attacks';
import { databaseDeepAttacks } from './database-deep-attacks';
import { networkAttacks } from './network-attacks';
import { aiVectorAttacks } from './ai-vector-attacks';
import { postgrestEdgeAttacks } from './postgrest-edge-attacks';
import { backupRecoveryAttacks } from './backup-recovery-attacks';
import { loggingAttacks } from './logging-attacks';

// NEW: Critical security attack modules (Round 3)
import { serviceRoleAttacks } from './service-role-attacks';
import { credentialsScannerAttacks } from './credentials-scanner-attacks';
import { rlsAnalyzerAttacks } from './rls-analyzer-attacks';
import { authEdgeCasesAttacks } from './auth-edge-cases-attacks';

/**
 * All attack vectors - 250+ comprehensive attacks
 */
export const ALL_ATTACKS: AttackVector[] = [
	// Core RLS attacks
	...rlsAttacks,
	...rlsAdvancedAttacks,

	// Auth attacks
	...authAttacks,
	...authAdvancedAttacks,
	...authEdgeAttacks,

	// Storage attacks
	...storageAttacks,
	...storageAdvancedAttacks,
	...storageTransformAttacks,

	// Functions & Realtime
	...functionsAttacks,
	...realtimeAttacks,
	...realtimeAdvancedAttacks,

	// Vibecoder attacks
	...vibecoderAttacks,
	...vibecoderAdvancedAttacks,

	// API & Database
	...apiAttacks,
	...databaseAttacks,
	...postgrestAdvancedAttacks,

	// Infrastructure & Security
	...infrastructureAttacks,
	...dataExposureAttacks,
	...injectionAttacks,
	...businessLogicAttacks,
	...dosAttacks,

	// NEW: Advanced attack categories
	...graphqlAttacks,
	...vaultAttacks,
	...multiTenantAttacks,
	...scheduledJobAttacks,
	...webhookAttacks,
	...extensionAttacks,
	...managementApiAttacks,

	// NEW: Deep attack categories (Round 2)
	...edgeFunctionsDeepAttacks,
	...authProviderAttacks,
	...databaseDeepAttacks,
	...networkAttacks,
	...aiVectorAttacks,
	...postgrestEdgeAttacks,
	...backupRecoveryAttacks,
	...loggingAttacks,

	// NEW: Critical security attacks (Round 3)
	...serviceRoleAttacks,
	...credentialsScannerAttacks,
	...rlsAnalyzerAttacks,
	...authEdgeCasesAttacks
];

/**
 * Get attacks by category
 */
export function getAttacksByCategory(category: string): AttackVector[] {
	return ALL_ATTACKS.filter((a) => a.category === category);
}

/**
 * Get attack by ID
 */
export function getAttackById(id: string): AttackVector | undefined {
	return ALL_ATTACKS.find((a) => a.id === id);
}

/**
 * Get attack count by category
 */
export function getAttackCountByCategory(): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const attack of ALL_ATTACKS) {
		counts[attack.category] = (counts[attack.category] || 0) + 1;
	}
	return counts;
}

/**
 * Get total attack count
 */
export function getTotalAttackCount(): number {
	return ALL_ATTACKS.length;
}

// Re-export individual modules
export { rlsAttacks } from './rls-attacks';
export { rlsAdvancedAttacks } from './rls-advanced-attacks';
export { authAttacks } from './auth-attacks';
export { authAdvancedAttacks } from './auth-advanced-attacks';
export { storageAttacks } from './storage-attacks';
export { storageAdvancedAttacks } from './storage-advanced-attacks';
export { functionsAttacks } from './functions-attacks';
export { realtimeAttacks } from './realtime-attacks';
export { vibecoderAttacks } from './vibecoder-attacks';
export { vibecoderAdvancedAttacks } from './vibecoder-advanced-attacks';
export { apiAttacks } from './api-attacks';
export { databaseAttacks } from './database-attacks';
export { infrastructureAttacks } from './infrastructure-attacks';
export { dataExposureAttacks } from './data-exposure-attacks';
export { injectionAttacks } from './injection-attacks';
export { businessLogicAttacks } from './business-logic-attacks';
export { dosAttacks } from './dos-attacks';

// NEW exports
export { graphqlAttacks } from './graphql-attacks';
export { vaultAttacks } from './vault-attacks';
export { multiTenantAttacks } from './multi-tenant-attacks';
export { authEdgeAttacks } from './auth-edge-attacks';
export { postgrestAdvancedAttacks } from './postgrest-advanced-attacks';
export { scheduledJobAttacks } from './scheduled-job-attacks';
export { webhookAttacks } from './webhook-attacks';
export { extensionAttacks } from './extension-attacks';
export { realtimeAdvancedAttacks } from './realtime-advanced-attacks';
export { storageTransformAttacks } from './storage-transform-attacks';
export { managementApiAttacks } from './management-api-attacks';

// NEW exports (Round 2)
export { edgeFunctionsDeepAttacks } from './edge-functions-deep-attacks';
export { authProviderAttacks } from './auth-provider-attacks';
export { databaseDeepAttacks } from './database-deep-attacks';
export { networkAttacks } from './network-attacks';
export { aiVectorAttacks } from './ai-vector-attacks';
export { postgrestEdgeAttacks } from './postgrest-edge-attacks';
export { backupRecoveryAttacks } from './backup-recovery-attacks';
export { loggingAttacks } from './logging-attacks';

// NEW exports (Round 3 - Critical Security)
export { serviceRoleAttacks } from './service-role-attacks';
export { credentialsScannerAttacks } from './credentials-scanner-attacks';
export { rlsAnalyzerAttacks } from './rls-analyzer-attacks';
export { authEdgeCasesAttacks } from './auth-edge-cases-attacks';
