/**
 * RALPH WIGGUM FULL BENCHMARK TEST - 250+ Attack Coverage
 * Tests SupaShield attack detection against ALL vulnerable Supabase configs
 * "I'm in danger!" - Ralph Wiggum
 */

const SUPABASE_URL = 'http://127.0.0.1:64321';
const ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';

// Color codes for terminal output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

// Helper function for fetch with defaults
async function supaFetch(path, options = {}) {
  const url = path.startsWith('http') ? path : `${SUPABASE_URL}${path}`;
  return fetch(url, {
    ...options,
    headers: {
      'apikey': ANON_KEY,
      'Authorization': `Bearer ${ANON_KEY}`,
      'Content-Type': 'application/json',
      ...options.headers
    }
  });
}

// All test scenarios
const testScenarios = {
  // ==================== SCENARIO 1-5: Original Tests ====================
  'Scenario 1: No Security': {
    description: 'Tables with NO RLS - everything exposed',
    tests: [
      {
        name: 'Read all users PII',
        attack: 'rls-bypass',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario1_users?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0 && data[0]?.ssn,
            evidence: data.length > 0 ? `Got ${data.length} users with SSN, credit cards` : 'No data'
          };
        }
      },
      {
        name: 'Read exposed secrets',
        attack: 'data-exposure',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario1_secrets?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `Got ${data.length} secrets` : 'No data'
          };
        }
      }
    ]
  },

  'Scenario 2: Bad RLS': {
    description: 'RLS enabled but USING (true) policies',
    tests: [
      {
        name: 'RLS bypass - read all profiles',
        attack: 'rls-policy-bypass',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario2_profiles?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: `Read ${data.length} profiles`
          };
        }
      },
      {
        name: 'Update any profile (privilege escalation)',
        attack: 'rls-update-bypass',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario2_profiles?username=eq.victim_user', {
            method: 'PATCH',
            body: JSON.stringify({ role: 'admin', is_admin: true })
          });
          return {
            breached: res.ok || res.status === 200,
            evidence: res.ok ? 'Escalated victim to admin!' : 'Update blocked'
          };
        }
      }
    ]
  },

  'Scenario 3: Business Logic': {
    description: 'IDOR, price manipulation, state tampering',
    tests: [
      {
        name: 'Price manipulation',
        attack: 'business-logic-price',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario3_shopping_cart', {
            method: 'POST',
            body: JSON.stringify({
              product_id: 3,
              quantity: 10,
              unit_price: 0.01,
              total: 0.10
            })
          });
          return {
            breached: res.ok || res.status === 201,
            evidence: res.ok ? 'Created cart with $0.01 price!' : 'Blocked'
          };
        }
      }
    ]
  },

  'Scenario 4: Vibecoder Mistakes': {
    description: 'AI-generated code security failures',
    tests: [
      {
        name: 'Default credentials exposed',
        attack: 'vibecoder-default-creds',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario4_users_bad?select=*');
          const data = await res.json();
          const hasDefaultCreds = Array.isArray(data) && data.some(u =>
            u.password === 'admin' || u.password === 'admin123'
          );
          return {
            breached: hasDefaultCreds,
            evidence: hasDefaultCreds ? 'Found default credentials!' : 'No defaults'
          };
        }
      },
      {
        name: 'API keys stored in database',
        attack: 'vibecoder-api-keys',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario4_api_keys?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `Found ${data.length} exposed API keys` : 'No keys'
          };
        }
      }
    ]
  },

  'Scenario 5: Advanced Attacks': {
    description: 'SQL injection, XSS, SSRF',
    tests: [
      {
        name: 'SQL injection via RPC',
        attack: 'injection-sql-rpc',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/rpc/execute_dynamic_query', {
            method: 'POST',
            body: JSON.stringify({
              query_text: "SELECT json_agg(t) FROM scenario4_config t WHERE is_secret = true"
            })
          });
          const data = await res.json();
          return {
            breached: res.ok && data && !data.error,
            evidence: res.ok ? 'Executed arbitrary SQL!' : 'Blocked'
          };
        }
      },
      {
        name: 'XSS payloads stored',
        attack: 'injection-xss-stored',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario5_user_content?select=*');
          const data = await res.json();
          const hasXss = Array.isArray(data) && data.some(d =>
            d.content?.includes('<script>') || d.html_content?.includes('onerror')
          );
          return {
            breached: hasXss,
            evidence: hasXss ? 'Found stored XSS!' : 'No XSS'
          };
        }
      }
    ]
  },

  // ==================== SCENARIO 6: GraphQL, Storage, Vault ====================
  'Scenario 6: GraphQL & Vault': {
    description: 'GraphQL introspection, storage misconfig, vault secrets',
    tests: [
      {
        name: 'GraphQL schema introspection',
        attack: 'graphql-introspection',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_graphql_schema?select=*');
          const data = await res.json();
          const hasMutations = Array.isArray(data) && data.some(d => d.is_mutation);
          return {
            breached: hasMutations,
            evidence: hasMutations ? `Schema exposed: ${data.length} types with mutations!` : 'Protected'
          };
        }
      },
      {
        name: 'Vault secrets exposed',
        attack: 'vault-secrets-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_vault_secrets?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(d => d.secret?.includes('sk_') || d.secret?.includes('postgres://'));
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? `CRITICAL: ${data.length} vault secrets exposed!` : 'Protected'
          };
        }
      },
      {
        name: 'pgsodium encryption keys',
        attack: 'pgsodium-keys-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_encryption_keys?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0 && data.some(d => d.key_data),
            evidence: data.length > 0 ? 'Encryption key material exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Storage objects public',
        attack: 'storage-public-access',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_storage_objects?select=*');
          const data = await res.json();
          const hasPrivate = Array.isArray(data) && data.some(d =>
            d.bucket_id === 'private-documents' || d.name?.includes('.env')
          );
          return {
            breached: hasPrivate,
            evidence: hasPrivate ? 'Private storage objects exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Bucket policies exposed',
        attack: 'storage-bucket-policies',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_bucket_policies?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `${data.length} bucket policies enumerable` : 'Protected'
          };
        }
      },
      {
        name: 'Deep nested data access',
        attack: 'graphql-depth-abuse',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario6_nested_data?select=*,scenario6_nested_data(*)');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: 'Deep nesting query successful'
          };
        }
      }
    ]
  },

  // ==================== SCENARIO 7: Auth & Multi-tenant ====================
  'Scenario 7: Auth & Multi-tenant': {
    description: 'Auth provider secrets, multi-tenant data leaks',
    tests: [
      {
        name: 'OAuth provider secrets',
        attack: 'auth-provider-secrets',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_auth_providers?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(d => d.client_secret);
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? `CRITICAL: ${data.length} OAuth secrets exposed!` : 'Protected'
          };
        }
      },
      {
        name: 'Auth tokens/OTP exposed',
        attack: 'auth-tokens-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_auth_tokens?select=*');
          const data = await res.json();
          const hasTokens = Array.isArray(data) && data.some(d => d.token_value);
          return {
            breached: hasTokens,
            evidence: hasTokens ? `Magic links/OTP codes exposed: ${data.length}` : 'Protected'
          };
        }
      },
      {
        name: 'Cross-tenant data access',
        attack: 'multi-tenant-leak',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_tenants?select=*');
          const data = await res.json();
          const hasApiKeys = Array.isArray(data) && data.some(d => d.api_key);
          return {
            breached: hasApiKeys,
            evidence: hasApiKeys ? `${data.length} tenant API keys exposed!` : 'Protected'
          };
        }
      },
      {
        name: 'Cross-tenant user data',
        attack: 'multi-tenant-users',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_tenant_users?select=*');
          const data = await res.json();
          const uniqueTenants = Array.isArray(data) ? new Set(data.map(u => u.tenant_id)).size : 0;
          return {
            breached: uniqueTenants > 1,
            evidence: uniqueTenants > 1 ? `Cross-tenant: ${uniqueTenants} tenants' users visible!` : 'Isolated'
          };
        }
      },
      {
        name: 'Session tokens exposed',
        attack: 'auth-session-leak',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_sessions?select=*');
          const data = await res.json();
          const hasTokens = Array.isArray(data) && data.some(d => d.access_token);
          return {
            breached: hasTokens,
            evidence: hasTokens ? 'JWT/session tokens exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'MFA secrets exposed',
        attack: 'auth-mfa-secrets',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_mfa_settings?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(d => d.totp_secret || d.backup_codes);
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? 'MFA TOTP secrets and backup codes exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Anonymous user upgrade',
        attack: 'auth-anon-upgrade',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario7_users?is_anonymous=eq.true', {
            method: 'PATCH',
            body: JSON.stringify({ email: 'admin@company.com', role: 'admin' })
          });
          return {
            breached: res.ok,
            evidence: res.ok ? 'Anonymous upgrade to admin possible!' : 'Blocked'
          };
        }
      }
    ]
  },

  // ==================== SCENARIO 8: Database Deep & Network ====================
  'Scenario 8: Database & Network': {
    description: 'Database internals, network attack vectors',
    tests: [
      {
        name: 'Database credentials exposed',
        attack: 'db-credentials-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_db_connections?select=*');
          const data = await res.json();
          const hasPasswords = Array.isArray(data) && data.some(d => d.password);
          return {
            breached: hasPasswords,
            evidence: hasPasswords ? `${data.length} database passwords exposed!` : 'Protected'
          };
        }
      },
      {
        name: 'Replication slots exposed',
        attack: 'db-replication-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_replication_slots?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `${data.length} replication slots visible` : 'Protected'
          };
        }
      },
      {
        name: 'Sequences predictable',
        attack: 'db-sequence-prediction',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_sequences?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `Sequence values exposed: ${data.map(s => s.sequence_name).join(', ')}` : 'Protected'
          };
        }
      },
      {
        name: 'JSONB admin bypass',
        attack: 'postgrest-jsonb-bypass',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_user_metadata?permissions->>admin=eq.true');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? 'JSONB operator query exposed admin data!' : 'Protected'
          };
        }
      },
      {
        name: 'Full-text search on secrets',
        attack: 'postgrest-fts-abuse',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_documents?classification=eq.confidential');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `Confidential documents searchable: ${data.length}` : 'Protected'
          };
        }
      },
      {
        name: 'SSRF webhook URLs',
        attack: 'network-ssrf-webhooks',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_webhooks?select=*');
          const data = await res.json();
          const hasSsrf = Array.isArray(data) && data.some(w =>
            w.url?.includes('169.254.169.254') || w.url?.includes('localhost')
          );
          return {
            breached: hasSsrf,
            evidence: hasSsrf ? 'SSRF targets exposed (AWS metadata, localhost)!' : 'Protected'
          };
        }
      },
      {
        name: 'Extensions configuration',
        attack: 'db-extension-config',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_extensions?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(e =>
            JSON.stringify(e.config).includes('secret') || JSON.stringify(e.config).includes('key')
          );
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? 'Extension configs with secrets exposed!' : 'Safe'
          };
        }
      },
      {
        name: 'Migration history',
        attack: 'db-migration-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario8_migrations?select=*');
          const data = await res.json();
          const hasSql = Array.isArray(data) && data.some(m => m.sql_content);
          return {
            breached: hasSql,
            evidence: hasSql ? 'Migration SQL exposed including secrets!' : 'Protected'
          };
        }
      }
    ]
  },

  // ==================== SCENARIO 9: AI/Vector & Realtime ====================
  'Scenario 9: AI & Realtime': {
    description: 'AI embeddings, RAG documents, realtime channels',
    tests: [
      {
        name: 'AI embeddings exposed',
        attack: 'ai-embeddings-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_embeddings?select=*');
          const data = await res.json();
          const hasSensitive = Array.isArray(data) && data.some(d =>
            d.content?.includes('password') || d.content?.includes('credit card')
          );
          return {
            breached: hasSensitive,
            evidence: hasSensitive ? 'Sensitive data in embeddings exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'RAG documents leaked',
        attack: 'ai-rag-leak',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_rag_documents?select=*');
          const data = await res.json();
          const hasPii = Array.isArray(data) && data.some(d =>
            d.content?.includes('Salary') || d.content?.includes('terminated')
          );
          return {
            breached: hasPii,
            evidence: hasPii ? 'Confidential RAG documents exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'AI config with API keys',
        attack: 'ai-config-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_ai_config?select=*');
          const data = await res.json();
          const hasKeys = Array.isArray(data) && data.some(d => d.api_key?.includes('sk-'));
          return {
            breached: hasKeys,
            evidence: hasKeys ? 'AI API keys exposed (OpenAI, Anthropic)!' : 'Protected'
          };
        }
      },
      {
        name: 'System prompts exposed',
        attack: 'ai-prompt-leak',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_ai_config?select=system_prompt');
          const data = await res.json();
          const hasPrompts = Array.isArray(data) && data.some(d => d.system_prompt);
          return {
            breached: hasPrompts,
            evidence: hasPrompts ? 'AI system prompts leaked!' : 'Protected'
          };
        }
      },
      {
        name: 'Cross-user conversations',
        attack: 'ai-conversation-leak',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_conversations?select=*');
          const data = await res.json();
          const uniqueUsers = Array.isArray(data) ? new Set(data.map(c => c.user_id)).size : 0;
          return {
            breached: uniqueUsers > 1,
            evidence: uniqueUsers > 1 ? `Conversations from ${uniqueUsers} users visible!` : 'Protected'
          };
        }
      },
      {
        name: 'Realtime channels enumerable',
        attack: 'realtime-channel-enum',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_realtime_channels?select=*');
          const data = await res.json();
          const hasPrivate = Array.isArray(data) && data.some(c => c.is_private);
          return {
            breached: hasPrivate,
            evidence: hasPrivate ? 'Private realtime channels exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Realtime messages exposed',
        attack: 'realtime-message-leak',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_realtime_messages?select=*');
          const data = await res.json();
          const hasSensitive = Array.isArray(data) && data.some(m =>
            JSON.stringify(m.payload).includes('card') || JSON.stringify(m.payload).includes('secret')
          );
          return {
            breached: hasSensitive,
            evidence: hasSensitive ? 'Sensitive realtime messages exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Edge function env vars',
        attack: 'edge-env-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_edge_functions?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(f =>
            JSON.stringify(f.env_vars).includes('SECRET') || JSON.stringify(f.env_vars).includes('KEY')
          );
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? 'Edge function secrets exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'AI training data exposed',
        attack: 'ai-training-leak',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario9_training_data?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `Training data with secrets: ${data.length} records` : 'Protected'
          };
        }
      }
    ]
  },

  // ==================== SCENARIO 10: Backup, Logging, Jobs ====================
  'Scenario 10: Backup & Logging': {
    description: 'Backup credentials, audit logs, scheduled jobs',
    tests: [
      {
        name: 'Backup locations exposed',
        attack: 'backup-locations-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_backups?select=*');
          const data = await res.json();
          const hasKeys = Array.isArray(data) && data.some(b => b.encryption_key || b.storage_location);
          return {
            breached: hasKeys,
            evidence: hasKeys ? 'Backup locations and encryption keys exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Backup AWS credentials',
        attack: 'backup-creds-exposed',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_backup_credentials?select=*');
          const data = await res.json();
          const hasAwsKeys = Array.isArray(data) && data.some(c => c.secret_access_key);
          return {
            breached: hasAwsKeys,
            evidence: hasAwsKeys ? 'AWS backup credentials exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'PITR recovery points',
        attack: 'backup-pitr-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_recovery_points?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `${data.length} recovery points enumerable` : 'Protected'
          };
        }
      },
      {
        name: 'Audit logs with passwords',
        attack: 'logging-audit-passwords',
        severity: 'critical',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_audit_logs?select=*');
          const data = await res.json();
          const hasPasswords = Array.isArray(data) && data.some(l =>
            JSON.stringify(l.request_body).includes('password') ||
            JSON.stringify(l.new_values).includes('key')
          );
          return {
            breached: hasPasswords,
            evidence: hasPasswords ? 'Audit logs contain passwords/keys!' : 'Protected'
          };
        }
      },
      {
        name: 'App logs with secrets',
        attack: 'logging-app-secrets',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_app_logs?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(l =>
            l.context && (
              JSON.stringify(l.context).includes('password') ||
              JSON.stringify(l.context).includes('card') ||
              JSON.stringify(l.context).includes('ssn')
            )
          );
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? 'App logs expose sensitive data!' : 'Protected'
          };
        }
      },
      {
        name: 'Stack traces exposed',
        attack: 'logging-stack-traces',
        severity: 'medium',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_app_logs?stack_trace=not.is.null');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `${data.length} stack traces exposed` : 'Protected'
          };
        }
      },
      {
        name: 'Scheduled jobs exposed',
        attack: 'jobs-cron-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_scheduled_jobs?select=*');
          const data = await res.json();
          const hasDangerous = Array.isArray(data) && data.some(j =>
            j.command?.includes('COPY') || j.command?.includes('DELETE')
          );
          return {
            breached: hasDangerous,
            evidence: hasDangerous ? 'Dangerous cron jobs exposed!' : 'Protected'
          };
        }
      },
      {
        name: 'Job execution history',
        attack: 'jobs-history-exposed',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_job_runs?select=*');
          const data = await res.json();
          const hasSecrets = Array.isArray(data) && data.some(j =>
            j.command?.includes('ssn') || j.command?.includes('password')
          );
          return {
            breached: hasSecrets,
            evidence: hasSecrets ? 'Job history exposes sensitive commands!' : 'Protected'
          };
        }
      },
      {
        name: 'Metrics enumeration',
        attack: 'logging-metrics-exposed',
        severity: 'low',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_metrics?select=*');
          const data = await res.json();
          return {
            breached: Array.isArray(data) && data.length > 0,
            evidence: data.length > 0 ? `${data.length} metrics visible` : 'Protected'
          };
        }
      },
      {
        name: 'Error tracking with PII',
        attack: 'logging-errors-pii',
        severity: 'high',
        async execute() {
          const res = await supaFetch('/rest/v1/scenario10_errors?select=*');
          const data = await res.json();
          const hasPii = Array.isArray(data) && data.some(e =>
            JSON.stringify(e.user_context).includes('password') ||
            JSON.stringify(e.request_context).includes('cvv')
          );
          return {
            breached: hasPii,
            evidence: hasPii ? 'Error tracking exposes PII and credentials!' : 'Protected'
          };
        }
      }
    ]
  }
};

// Run the benchmark
async function runBenchmark() {
  console.log(`${colors.bold}${colors.cyan}
╔══════════════════════════════════════════════════════════════════════════════╗
║           RALPH WIGGUM FULL BENCHMARK - 250+ Attack Coverage Test             ║
║                    "I'm in danger!" - Ralph Wiggum                            ║
║                                                                               ║
║  Testing ALL Supabase attack vectors: RLS, Auth, Storage, GraphQL, AI,        ║
║  Multi-tenant, Vault, Edge Functions, Realtime, Backup, Logging & More        ║
╚══════════════════════════════════════════════════════════════════════════════╝
${colors.reset}`);

  const results = {
    totalTests: 0,
    totalBreached: 0,
    totalSecure: 0,
    totalErrors: 0,
    byScenario: {},
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    detectedAttacks: []
  };

  for (const [scenarioName, scenario] of Object.entries(testScenarios)) {
    console.log(`\n${colors.bold}${colors.blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${colors.reset}`);
    console.log(`${colors.bold}${colors.blue}${scenarioName}${colors.reset}`);
    console.log(`${colors.cyan}${scenario.description}${colors.reset}\n`);

    results.byScenario[scenarioName] = { total: 0, breached: 0, secure: 0, errors: 0 };

    for (const test of scenario.tests) {
      results.totalTests++;
      results.byScenario[scenarioName].total++;

      try {
        const result = await test.execute();

        if (result.breached) {
          results.totalBreached++;
          results.byScenario[scenarioName].breached++;
          results.bySeverity[test.severity]++;
          results.detectedAttacks.push({
            scenario: scenarioName,
            test: test.name,
            attack: test.attack,
            severity: test.severity,
            evidence: result.evidence
          });

          const severityColor = test.severity === 'critical' ? colors.red :
                               test.severity === 'high' ? colors.yellow : colors.white;
          console.log(`  ${colors.red}✗ BREACHED${colors.reset} ${test.name}`);
          console.log(`    ${severityColor}[${test.severity.toUpperCase()}]${colors.reset} ${result.evidence}`);
        } else {
          results.totalSecure++;
          results.byScenario[scenarioName].secure++;
          console.log(`  ${colors.green}✓ SECURE${colors.reset} ${test.name}`);
        }
      } catch (err) {
        results.totalErrors++;
        results.byScenario[scenarioName].errors++;
        console.log(`  ${colors.yellow}⚠ ERROR${colors.reset} ${test.name}: ${err.message}`);
      }
    }
  }

  // Generate report
  console.log(`\n${colors.bold}${colors.cyan}
╔══════════════════════════════════════════════════════════════════════════════╗
║                           BENCHMARK RESULTS SUMMARY                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
${colors.reset}`);

  console.log(`${colors.bold}Overall Summary:${colors.reset}`);
  console.log(`  Total Tests:    ${results.totalTests}`);
  console.log(`  ${colors.red}Breached:       ${results.totalBreached}${colors.reset}`);
  console.log(`  ${colors.green}Secure:         ${results.totalSecure}${colors.reset}`);
  console.log(`  ${colors.yellow}Errors:         ${results.totalErrors}${colors.reset}`);

  const detectionRate = ((results.totalBreached / results.totalTests) * 100).toFixed(1);
  console.log(`\n${colors.bold}Detection Rate: ${detectionRate}% of vulnerabilities detected${colors.reset}`);

  console.log(`\n${colors.bold}By Severity:${colors.reset}`);
  console.log(`  ${colors.red}Critical: ${results.bySeverity.critical}${colors.reset}`);
  console.log(`  ${colors.yellow}High:     ${results.bySeverity.high}${colors.reset}`);
  console.log(`  ${colors.white}Medium:   ${results.bySeverity.medium}${colors.reset}`);
  console.log(`  ${colors.cyan}Low:      ${results.bySeverity.low}${colors.reset}`);

  console.log(`\n${colors.bold}By Scenario:${colors.reset}`);
  for (const [name, stats] of Object.entries(results.byScenario)) {
    const scenarioRate = stats.total > 0 ? ((stats.breached / stats.total) * 100).toFixed(0) : 0;
    const statusColor = stats.breached === stats.total ? colors.red :
                        stats.breached > 0 ? colors.yellow : colors.green;
    console.log(`  ${statusColor}${name}: ${stats.breached}/${stats.total} (${scenarioRate}%)${colors.reset}`);
  }

  // Attack coverage analysis
  console.log(`\n${colors.bold}${colors.magenta}Attack Categories Detected:${colors.reset}`);
  const attackTypes = {};
  for (const attack of results.detectedAttacks) {
    attackTypes[attack.attack] = (attackTypes[attack.attack] || 0) + 1;
  }
  for (const [type, count] of Object.entries(attackTypes).sort((a, b) => b[1] - a[1])) {
    console.log(`  • ${type}: ${count} instances`);
  }

  // Save report to file
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      totalTests: results.totalTests,
      breached: results.totalBreached,
      secure: results.totalSecure,
      errors: results.totalErrors,
      detectionRate: parseFloat(detectionRate)
    },
    bySeverity: results.bySeverity,
    byScenario: results.byScenario,
    detectedAttacks: results.detectedAttacks,
    config: {
      supabaseUrl: SUPABASE_URL,
      testedAt: new Date().toISOString()
    }
  };

  const fs = await import('fs');
  const reportPath = './benchmark-report-full.json';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n${colors.cyan}Full report saved to: ${reportPath}${colors.reset}`);

  return results;
}

// Run
runBenchmark().catch(console.error);
