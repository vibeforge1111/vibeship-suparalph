# SupaRalph

**"I'm in danger!"** - Supabase Penetration Testing Tool

SupaRalph is an open-source security scanner that actively tests your Supabase project for vulnerabilities. Unlike static analyzers, SupaRalph actually attempts to exploit your database to prove what's broken.

![Attacks](https://img.shields.io/badge/attacks-277-red) ![License](https://img.shields.io/badge/license-MIT-green) ![Supabase](https://img.shields.io/badge/supabase-compatible-3ecf8e)

## Features

- **277 Attack Vectors** - Comprehensive coverage of all Supabase attack surfaces
- **Real-time Scanning** - Watch attacks execute live in a terminal UI
- **Zero Data Persistence** - No credentials or results stored (session-only)
- **AI-Powered Fixes** - Copy findings to Supabase AI for tailored SQL fixes
- **CI/CD Integration** - GitHub Action for automated security scanning
- **Compliance Mapping** - OWASP Top 10, SOC2, and GDPR coverage
- **Multiple Report Formats** - JSON, Markdown, and HTML reports

## Attack Categories

| Category | Attacks | Description |
|----------|---------|-------------|
| RLS | 100+ | Row Level Security bypass, USING(true), missing policies |
| Auth | 43+ | Weak passwords, MFA bypass, JWT manipulation, session attacks |
| API | 39+ | GraphQL introspection, CORS, security headers, credentials |
| Storage | 23+ | Public buckets, path traversal, file type abuse |
| Functions | 15+ | Edge function auth bypass, rate limit bypass |
| Database | 14+ | Direct access, injection, extension abuse |
| Vibecoder | 13+ | Common AI-generated code mistakes |
| Realtime | 13+ | Subscription leaks, channel hijacking |

## Quick Start

### Option 1: Run Locally

```bash
# Clone the repository
git clone https://github.com/vibeforge1111/vibeship-supascanner.git
cd vibeship-supascanner

# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) and enter your Supabase project URL.

### Option 2: Demo Mode

Enter `demo` as the URL to see a simulated scan without connecting to a real project.

## Usage

### 1. Get your Supabase URL

- Go to [supabase.com/dashboard](https://supabase.com/dashboard)
- Select your project → Settings → API
- Copy the **Project URL**

### 2. Run a Scan

- Paste your URL into SupaRalph
- Optionally add your anon key for deeper testing
- Click "BREACH TEST"

### 3. Review Results

- Watch attacks execute in real-time
- See which vulnerabilities were found
- Copy findings for AI-powered fixes

### 4. Fix Vulnerabilities

- Click "Copy Findings for AI"
- Open [Supabase SQL Editor](https://supabase.com/dashboard/project/_/sql/new)
- Paste and ask AI to generate fixes

## CI/CD Integration

Add automated security scanning to your GitHub workflows. Copy `.github/workflows/suparalph-scan.yml` to your repository and add these secrets:

- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_ANON_KEY` - Your anon/public key

The action will:
- Run security scans on every push/PR
- Comment findings directly on PRs
- Optionally fail builds on critical vulnerabilities

## Security & Privacy

SupaRalph is designed with security in mind:

- **Zero Persistence** - No credentials or scan results are stored
- **Session Only** - All data cleared when you close the browser
- **No Server Storage** - Scans run client-side, nothing sent to our servers
- **Open Source** - Full code transparency

## Report Formats

Generate reports in multiple formats:

```typescript
import { generateJSONReport, generateMarkdownReport, generateHTMLReport } from '$lib/engine/reports';

// JSON - Machine-readable with full evidence
const json = generateJSONReport(report, { includeEvidence: true });

// Markdown - Documentation-friendly
const md = generateMarkdownReport(report, { includeCompliance: true });

// HTML - Shareable web report
const html = generateHTMLReport(report);
```

## Compliance Mapping

SupaRalph maps vulnerabilities to compliance frameworks:

| Framework | Coverage |
|-----------|----------|
| OWASP Top 10 2021 | A01-A10 mapped |
| SOC2 | CC6.1, CC6.6, CC6.7 |
| GDPR | Articles 32, 33 |

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Type check
npm run check

# Build for production
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
src/
├── lib/
│   ├── components/        # UI components
│   ├── engine/
│   │   ├── attacks/       # 40 attack modules (277 vectors)
│   │   ├── fixes/         # Fix rulesets
│   │   └── reports/       # Report generation
│   ├── stores/            # Svelte stores (session-only)
│   └── types/             # TypeScript types
└── routes/
    ├── +page.svelte       # Home/scanner with terminal
    ├── dashboard/         # Results dashboard
    ├── api/scan/          # SSE scan endpoint
    └── settings/          # Configuration
```

## Adding New Attacks

1. Create a new file in `src/lib/engine/attacks/`
2. Export an array of `AttackVector` objects
3. Import and add to `ALL_ATTACKS` in `index.ts`

```typescript
export const myAttacks: AttackVector[] = [
  {
    id: 'my-attack-id',
    name: 'My Attack Name',
    description: 'What this attack does',
    category: 'rls',
    severity: 'critical',
    async execute(ctx) {
      // Attack logic here
      return {
        breached: true,
        status: 'breached',
        summary: 'What was found',
        evidence: { /* proof */ }
      };
    }
  }
];
```

## Tech Stack

- **Framework**: SvelteKit 2 with Svelte 5 runes
- **Styling**: Tailwind CSS
- **Language**: TypeScript
- **Real-time**: Server-Sent Events (SSE)

## Disclaimer

**For authorized testing only.** Only scan Supabase projects you own or have explicit permission to test. SupaRalph performs real attacks that could affect data. Use responsibly.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*"I'm in danger!"* - Ralph Wiggum
