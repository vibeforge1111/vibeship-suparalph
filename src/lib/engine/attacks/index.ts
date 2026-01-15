/**
 * SupaShield Attack Playbook
 * Complete collection of attack vectors for all categories
 */

import type { AttackVector } from '$lib/types/attacks';
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

/**
 * All attack vectors
 */
export const ALL_ATTACKS: AttackVector[] = [
	...rlsAttacks,
	...rlsAdvancedAttacks,
	...authAttacks,
	...authAdvancedAttacks,
	...storageAttacks,
	...storageAdvancedAttacks,
	...functionsAttacks,
	...realtimeAttacks,
	...vibecoderAttacks,
	...vibecoderAdvancedAttacks,
	...apiAttacks,
	...databaseAttacks,
	...infrastructureAttacks,
	...dataExposureAttacks,
	...injectionAttacks,
	...businessLogicAttacks,
	...dosAttacks
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
