// SupaShield Library Exports
// Reexport all public APIs

// Supabase client
export {
	createAttackerClient,
	createAdminClient,
	testConnection,
	connect,
	getConnection,
	clearConnection,
	SupabaseCredentialsSchema,
	type SupabaseCredentials,
	type ConnectionTestResult,
	type SupaShieldConnection
} from './supabase/client';
