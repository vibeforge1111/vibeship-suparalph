/**
 * GraphQL-specific attacks for Supabase
 * Supabase exposes GraphQL at /graphql/v1
 */

import type { AttackVector } from '$lib/types/attacks';

export const graphqlAttacks: AttackVector[] = [
	{
		id: 'graphql-introspection-enabled',
		name: 'GraphQL Introspection Enabled',
		description: 'Check if GraphQL introspection is enabled exposing full schema',
		category: 'rls',
		severity: 'high',
		async execute(context) {
			const introspectionQuery = `
				query IntrospectionQuery {
					__schema {
						types {
							name
							fields {
								name
								type {
									name
								}
							}
						}
					}
				}
			`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: introspectionQuery }),
					signal: context.signal
				});

				const data = await res.json();
				const hasSchema = data?.data?.__schema?.types?.length > 0;

				return {
					breached: hasSchema,
					status: hasSchema ? 'breached' : 'secure',
					summary: hasSchema
						? `Introspection enabled - found ${data.data.__schema.types.length} types`
						: 'Introspection disabled or restricted',
					evidence: hasSchema ? { typeCount: data.data.__schema.types.length } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-query-depth',
		name: 'GraphQL Query Depth Attack',
		description: 'Test for deeply nested queries that could cause DoS',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			// Create deeply nested query
			const deepQuery = `
				query DeepQuery {
					usersCollection {
						edges {
							node {
								id
								postsCollection {
									edges {
										node {
											id
											commentsCollection {
												edges {
													node {
														id
														authorCollection {
															edges {
																node {
																	id
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: deepQuery }),
					signal: context.signal
				});

				const data = await res.json();
				const hasDepthLimit = data?.errors?.some((e: { message: string }) =>
					e.message?.toLowerCase().includes('depth') ||
					e.message?.toLowerCase().includes('complexity')
				);

				return {
					breached: !hasDepthLimit && !data?.errors,
					status: hasDepthLimit ? 'secure' : 'breached',
					summary: hasDepthLimit
						? 'Query depth limiting is enforced'
						: 'No query depth limits detected - DoS risk',
					evidence: data?.errors ? { errors: data.errors } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-batching-attack',
		name: 'GraphQL Batching Attack',
		description: 'Test for query batching that could amplify attacks',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			// Send batched queries
			const batchedQueries = Array(10).fill(null).map((_, i) => ({
				query: `query Q${i} { __typename }`
			}));

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify(batchedQueries),
					signal: context.signal
				});

				const data = await res.json();
				const batchAccepted = Array.isArray(data) && data.length === 10;

				return {
					breached: batchAccepted,
					status: batchAccepted ? 'breached' : 'secure',
					summary: batchAccepted
						? 'Query batching allowed - amplification attacks possible'
						: 'Query batching restricted or disabled',
					evidence: batchAccepted ? { batchSize: data.length } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-alias-abuse',
		name: 'GraphQL Alias Abuse',
		description: 'Test for alias-based query amplification',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			// Create query with many aliases
			const aliases = Array(50).fill(null).map((_, i) => `a${i}: __typename`).join('\n');
			const aliasQuery = `query AliasAbuse { ${aliases} }`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: aliasQuery }),
					signal: context.signal
				});

				const data = await res.json();
				const aliasesAccepted = data?.data && Object.keys(data.data).length >= 50;

				return {
					breached: aliasesAccepted,
					status: aliasesAccepted ? 'breached' : 'secure',
					summary: aliasesAccepted
						? 'Alias abuse possible - 50+ aliases accepted'
						: 'Alias limiting enforced',
					evidence: aliasesAccepted ? { aliasCount: Object.keys(data.data).length } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-fragment-cycle',
		name: 'GraphQL Fragment Cycle Attack',
		description: 'Test for circular fragment references',
		category: 'rls',
		severity: 'medium',
		async execute(context) {
			const cyclicQuery = `
				query CyclicFragments {
					__typename
					...FragA
				}
				fragment FragA on Query {
					__typename
					...FragB
				}
				fragment FragB on Query {
					__typename
					...FragA
				}
			`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: cyclicQuery }),
					signal: context.signal
				});

				const data = await res.json();
				const cycleDetected = data?.errors?.some((e: { message: string }) =>
					e.message?.toLowerCase().includes('cycle') ||
					e.message?.toLowerCase().includes('circular')
				);

				return {
					breached: !cycleDetected && !data?.errors,
					status: cycleDetected ? 'secure' : 'breached',
					summary: cycleDetected
						? 'Fragment cycle detection enabled'
						: 'No fragment cycle detection - DoS risk',
					evidence: data?.errors ? { errors: data.errors } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-field-suggestion',
		name: 'GraphQL Field Suggestion Leak',
		description: 'Check if GraphQL suggests valid field names in errors',
		category: 'rls',
		severity: 'low',
		async execute(context) {
			const badQuery = `query { usersCollection { edges { node { nonexistentfield12345 } } } }`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: badQuery }),
					signal: context.signal
				});

				const data = await res.json();
				const hasSuggestions = data?.errors?.some((e: { message: string }) =>
					e.message?.toLowerCase().includes('did you mean')
				);

				return {
					breached: hasSuggestions,
					status: hasSuggestions ? 'breached' : 'secure',
					summary: hasSuggestions
						? 'Field suggestions enabled - schema enumeration possible'
						: 'Field suggestions disabled',
					evidence: hasSuggestions ? { errors: data.errors } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-mutations-exposed',
		name: 'GraphQL Mutations Exposed',
		description: 'Check if dangerous mutations are exposed without auth',
		category: 'rls',
		severity: 'critical',
		async execute(context) {
			const mutationIntrospection = `
				query {
					__schema {
						mutationType {
							fields {
								name
								args {
									name
									type {
										name
									}
								}
							}
						}
					}
				}
			`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: mutationIntrospection }),
					signal: context.signal
				});

				const data = await res.json();
				const mutations = data?.data?.__schema?.mutationType?.fields || [];
				const dangerousMutations = mutations.filter((m: { name: string }) =>
					m.name.toLowerCase().includes('delete') ||
					m.name.toLowerCase().includes('update') ||
					m.name.toLowerCase().includes('insert')
				);

				return {
					breached: dangerousMutations.length > 0,
					status: dangerousMutations.length > 0 ? 'breached' : 'secure',
					summary: dangerousMutations.length > 0
						? `Found ${dangerousMutations.length} potentially dangerous mutations`
						: 'No dangerous mutations exposed',
					evidence: dangerousMutations.length > 0 ? { mutations: dangerousMutations.map((m: { name: string }) => m.name) } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	},
	{
		id: 'graphql-subscription-exposed',
		name: 'GraphQL Subscriptions Exposed',
		description: 'Check if GraphQL subscriptions leak real-time data',
		category: 'realtime',
		severity: 'high',
		async execute(context) {
			const subscriptionIntrospection = `
				query {
					__schema {
						subscriptionType {
							fields {
								name
							}
						}
					}
				}
			`;

			try {
				const res = await fetch(`${context.supabaseUrl}/graphql/v1`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'apikey': context.anonKey,
						'Authorization': `Bearer ${context.anonKey}`
					},
					body: JSON.stringify({ query: subscriptionIntrospection }),
					signal: context.signal
				});

				const data = await res.json();
				const subscriptions = data?.data?.__schema?.subscriptionType?.fields || [];

				return {
					breached: subscriptions.length > 0,
					status: subscriptions.length > 0 ? 'breached' : 'secure',
					summary: subscriptions.length > 0
						? `Found ${subscriptions.length} GraphQL subscriptions exposed`
						: 'No subscriptions exposed',
					evidence: subscriptions.length > 0 ? { subscriptions: subscriptions.map((s: { name: string }) => s.name) } : undefined
				};
			} catch {
				return { breached: false, status: 'error', summary: 'GraphQL endpoint not accessible' };
			}
		}
	}
];
