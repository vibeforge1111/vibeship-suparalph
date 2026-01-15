/**
 * SupaShield Supabase Client - Dual Context Connection System
 *
 * This module provides two Supabase clients:
 * 1. attackerClient - Uses anon key (simulates attacker with public access)
 * 2. adminClient - Uses service key (verifies findings, applies fixes)
 *
 * CRITICAL: Never expose the adminClient to frontend code
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';

// Validation schemas for credentials
export const SupabaseCredentialsSchema = z.object({
	url: z.string().url('Invalid Supabase URL'),
	anonKey: z.string().min(20, 'Anon key is too short'),
	serviceKey: z.string().min(20, 'Service key is too short').optional()
});

export type SupabaseCredentials = z.infer<typeof SupabaseCredentialsSchema>;

// Connection test result
export interface ConnectionTestResult {
	success: boolean;
	error?: string;
	projectRef?: string;
	version?: string;
	anonConnected: boolean;
	adminConnected: boolean;
}

/**
 * Creates an attacker context Supabase client (anon key only)
 * This simulates what a malicious actor would have access to
 */
export function createAttackerClient(url: string, anonKey: string): SupabaseClient {
	return createClient(url, anonKey, {
		auth: {
			autoRefreshToken: false,
			persistSession: false,
			detectSessionInUrl: false
		}
	});
}

/**
 * Creates an admin context Supabase client (service key)
 * This is used to verify findings and apply fixes
 * NEVER expose this to client-side code
 */
export function createAdminClient(url: string, serviceKey: string): SupabaseClient {
	return createClient(url, serviceKey, {
		auth: {
			autoRefreshToken: false,
			persistSession: false,
			detectSessionInUrl: false
		}
	});
}

/**
 * Test connection to a Supabase project
 * Validates both anon and admin access
 */
export async function testConnection(credentials: SupabaseCredentials): Promise<ConnectionTestResult> {
	const result: ConnectionTestResult = {
		success: false,
		anonConnected: false,
		adminConnected: false
	};

	try {
		// Validate credentials
		const validated = SupabaseCredentialsSchema.parse(credentials);

		// Test anon connection
		const attackerClient = createAttackerClient(validated.url, validated.anonKey);

		// Try to query something basic (won't fail even if RLS blocks it)
		const { error: anonError } = await attackerClient.from('_dummy_test_').select('*').limit(1);

		// 42P01 = table doesn't exist, which is fine - we just want to test the connection
		if (anonError && anonError.code !== '42P01' && anonError.code !== 'PGRST116') {
			result.error = `Anon connection failed: ${anonError.message}`;
			return result;
		}

		result.anonConnected = true;

		// Test admin connection if service key provided
		if (validated.serviceKey) {
			const adminClient = createAdminClient(validated.url, validated.serviceKey);

			// Admin should be able to query pg_tables
			const { error: adminError } = await adminClient.rpc('version');

			if (adminError && adminError.code !== 'PGRST202') {
				// PGRST202 = function doesn't exist, try another approach
				const { error: tableError } = await adminClient.from('_dummy_test_').select('*').limit(1);

				if (tableError && tableError.code !== '42P01' && tableError.code !== 'PGRST116') {
					result.error = `Admin connection failed: ${tableError.message}`;
					return result;
				}
			}

			result.adminConnected = true;
		}

		// Extract project ref from URL
		const urlMatch = validated.url.match(/https:\/\/([^.]+)\.supabase\.co/);
		if (urlMatch) {
			result.projectRef = urlMatch[1];
		}

		result.success = true;
		return result;
	} catch (error) {
		if (error instanceof z.ZodError) {
			result.error = `Validation failed: ${error.errors.map((e) => e.message).join(', ')}`;
		} else if (error instanceof Error) {
			result.error = error.message;
		} else {
			result.error = 'Unknown error occurred';
		}
		return result;
	}
}

/**
 * Connection state management
 */
export interface SupaShieldConnection {
	credentials: SupabaseCredentials;
	attackerClient: SupabaseClient;
	adminClient: SupabaseClient | null;
	projectRef: string;
	connectedAt: Date;
}

let currentConnection: SupaShieldConnection | null = null;

export function getConnection(): SupaShieldConnection | null {
	return currentConnection;
}

export function setConnection(connection: SupaShieldConnection): void {
	currentConnection = connection;
}

export function clearConnection(): void {
	currentConnection = null;
}

export async function connect(credentials: SupabaseCredentials): Promise<SupaShieldConnection> {
	const testResult = await testConnection(credentials);

	if (!testResult.success) {
		throw new Error(testResult.error || 'Connection failed');
	}

	const connection: SupaShieldConnection = {
		credentials,
		attackerClient: createAttackerClient(credentials.url, credentials.anonKey),
		adminClient: credentials.serviceKey
			? createAdminClient(credentials.url, credentials.serviceKey)
			: null,
		projectRef: testResult.projectRef || 'unknown',
		connectedAt: new Date()
	};

	setConnection(connection);
	return connection;
}
