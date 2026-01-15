# SupaShield (vibeship-supascanner)

**Supabase Security Scanner** - Breach testing tool for Supabase projects

## Overview

SupaShield is a comprehensive security testing tool that identifies vulnerabilities in Supabase projects. It includes **105 attack vectors** across 17 categories, covering:

- Row Level Security (RLS) bypass
- Authentication & authorization flaws
- Business logic vulnerabilities
- Common AI/vibecoder code mistakes
- SQL injection & advanced attacks
- Data exposure patterns
- Infrastructure misconfigurations
- DoS vectors

## Features

- **105 Attack Vectors** organized into 17 attack files
- **Breach Engine** with controlled concurrency and timeout handling
- **Real-time Progress** tracking during scans
- **Detailed Reports** with severity ratings and fix recommendations
- **SvelteKit UI** for easy project configuration and result viewing

## Attack Categories

| Category | Attacks | Description |
|----------|---------|-------------|
| RLS | 16 | Row Level Security bypass techniques |
| Auth | 14 | Authentication/authorization flaws |
| Vibecoder | 14 | Common AI-generated code mistakes |
| Business Logic | 7 | IDOR, state manipulation, price tampering |
| Injection | 6 | SQL injection, type confusion, encoding bypass |
| Infrastructure | 8 | Version disclosure, config exposure |
| Data Exposure | 8 | PII, secrets, logs exposure |
| DoS | 6 | Resource exhaustion attacks |
| Storage | 12 | Bucket policy and file access attacks |
| Functions | 5 | Edge function vulnerabilities |
| Realtime | 5 | Subscription and broadcast attacks |
| API | 6 | PostgREST API security |
| Database | 6 | Direct database attack patterns |

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Configuration

Create a `.env` file based on `.env.example`:

```env
PUBLIC_SUPABASE_URL=your-project-url
PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_KEY=your-service-key
```

## Usage

1. Enter your Supabase project URL and keys
2. Select attack categories to test
3. Run the scan
4. Review vulnerabilities and recommendations

## Benchmark Results

Tested against intentionally vulnerable Supabase configurations (Ralph Wiggum scenarios):

| Scenario | Tests | Detected | Rate |
|----------|-------|----------|------|
| No Security | 4 | 4 | 100% |
| Bad RLS | 4 | 4 | 100% |
| Business Logic | 5 | 5 | 100% |
| Vibecoder | 5 | 5 | 100% |
| Advanced | 6 | 6 | 100% |
| **Total** | **24** | **24** | **100%** |

## Tech Stack

- **Frontend**: SvelteKit 2, Svelte 5 runes
- **Styling**: Tailwind CSS
- **Backend**: Supabase client SDK
- **Language**: TypeScript

## Project Structure

```
src/
├── lib/
│   ├── components/     # UI components
│   ├── engine/
│   │   ├── attacks/    # 17 attack modules (105 vectors)
│   │   └── breach-engine.ts  # Core orchestration
│   ├── stores/         # Svelte stores
│   ├── supabase/       # Supabase client
│   └── types/          # TypeScript types
└── routes/
    ├── +page.svelte    # Home/scanner
    ├── dashboard/      # Results dashboard
    └── settings/       # Configuration
```

## Security Notice

This tool is for **authorized security testing only**. Only scan Supabase projects you own or have explicit permission to test. Unauthorized scanning may violate terms of service and laws.

## License

MIT
