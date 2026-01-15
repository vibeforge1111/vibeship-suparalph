/**
 * SupaRalph Scan API - Real breach testing endpoint
 * Runs the Ralph Wiggum loop against target Supabase
 *
 * RATE LIMITING: Prevents abuse by limiting requests per IP
 * - 5 scans per IP per 15 minutes for POST (full scan)
 * - 10 scans per IP per 15 minutes for GET (SSE streaming)
 */

import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { BreachEngine } from '$lib/engine/breach-engine';
import { ALL_ATTACKS, getTotalAttackCount } from '$lib/engine/attacks';

// In-memory rate limiter (resets on server restart)
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const POST_RATE_LIMIT = 5; // 5 full scans per window
const GET_RATE_LIMIT = 10; // 10 SSE scans per window

function getRateLimitKey(ip: string, method: string): string {
	return `${ip}:${method}`;
}

function checkRateLimit(ip: string, method: string): { allowed: boolean; remaining: number; resetIn: number } {
	const key = getRateLimitKey(ip, method);
	const now = Date.now();
	const limit = method === 'POST' ? POST_RATE_LIMIT : GET_RATE_LIMIT;

	const entry = rateLimitStore.get(key);

	// No entry or window expired - create new entry
	if (!entry || now > entry.resetAt) {
		rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
		return { allowed: true, remaining: limit - 1, resetIn: RATE_LIMIT_WINDOW };
	}

	// Within window - check count
	if (entry.count >= limit) {
		return { allowed: false, remaining: 0, resetIn: entry.resetAt - now };
	}

	// Increment count
	entry.count++;
	return { allowed: true, remaining: limit - entry.count, resetIn: entry.resetAt - now };
}

function getClientIP(request: Request): string {
	// Check common headers for real IP (when behind proxy/CDN)
	const forwarded = request.headers.get('x-forwarded-for');
	if (forwarded) {
		return forwarded.split(',')[0].trim();
	}
	const realIP = request.headers.get('x-real-ip');
	if (realIP) {
		return realIP;
	}
	// Fallback - will be 127.0.0.1 in dev
	return 'unknown';
}

export const POST: RequestHandler = async ({ request }) => {
	// Rate limit check
	const clientIP = getClientIP(request);
	const rateLimit = checkRateLimit(clientIP, 'POST');

	if (!rateLimit.allowed) {
		return json(
			{
				error: 'Rate limit exceeded. Please wait before scanning again.',
				retryAfter: Math.ceil(rateLimit.resetIn / 1000)
			},
			{
				status: 429,
				headers: {
					'Retry-After': String(Math.ceil(rateLimit.resetIn / 1000)),
					'X-RateLimit-Remaining': '0',
					'X-RateLimit-Reset': String(Math.ceil(rateLimit.resetIn / 1000))
				}
			}
		);
	}

	try {
		const body = await request.json();
		const { targetUrl, anonKey, serviceKey } = body;

		if (!targetUrl) {
			return json({ error: 'Missing targetUrl' }, { status: 400 });
		}

		// Create breach engine with callbacks for progress tracking
		const results: any[] = [];
		const vulnerabilities: any[] = [];
		let completed = 0;
		const total = getTotalAttackCount();

		const engine = new BreachEngine(
			{
				concurrency: 5,
				attackTimeout: 15000,
				delayBetweenAttacks: 50,
				stopOnBreach: false
			},
			{
				onAttackComplete: (attack, result) => {
					results.push({
						attackId: attack.id,
						name: attack.name,
						category: attack.category,
						severity: attack.severity,
						breached: result.breached,
						summary: result.summary
					});
				},
				onVulnerabilityFound: (vuln) => {
					vulnerabilities.push(vuln);
				},
				onProgress: (done, total) => {
					completed = done;
				}
			}
		);

		// Run the breach test
		const report = await engine.run(ALL_ATTACKS, {
			targetUrl,
			anonKey: anonKey || '',
			serviceKey: serviceKey || ''
		});

		return json({
			success: true,
			report: {
				id: report.id,
				stats: report.stats,
				vulnerabilities: report.vulnerabilities.length,
				duration: report.duration,
				byCategory: report.byCategory,
				bySeverity: report.bySeverity
			},
			breaches: vulnerabilities.slice(0, 20), // Top 20 vulnerabilities
			totalAttacks: total
		});
	} catch (error) {
		console.error('Scan error:', error);
		return json(
			{ error: error instanceof Error ? error.message : 'Scan failed' },
			{ status: 500 }
		);
	}
};

/**
 * GET endpoint for Server-Sent Events (streaming progress)
 */
export const GET: RequestHandler = async ({ url, request }) => {
	// Rate limit check
	const clientIP = getClientIP(request);
	const rateLimit = checkRateLimit(clientIP, 'GET');

	if (!rateLimit.allowed) {
		return json(
			{
				error: 'Rate limit exceeded. Please wait before scanning again.',
				retryAfter: Math.ceil(rateLimit.resetIn / 1000)
			},
			{
				status: 429,
				headers: {
					'Retry-After': String(Math.ceil(rateLimit.resetIn / 1000)),
					'X-RateLimit-Remaining': '0',
					'X-RateLimit-Reset': String(Math.ceil(rateLimit.resetIn / 1000))
				}
			}
		);
	}

	const targetUrl = url.searchParams.get('targetUrl');
	const anonKey = url.searchParams.get('anonKey') || '';

	if (!targetUrl) {
		return json({ error: 'Missing targetUrl' }, { status: 400 });
	}

	// Create a readable stream for SSE
	const stream = new ReadableStream({
		async start(controller) {
			const encoder = new TextEncoder();
			const send = (event: string, data: any) => {
				controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
			};

			let completed = 0;
			const total = getTotalAttackCount();
			const breaches: any[] = [];

			const engine = new BreachEngine(
				{
					concurrency: 5,
					attackTimeout: 10000,
					delayBetweenAttacks: 30,
					stopOnBreach: false
				},
				{
					onAttackStart: (attack) => {
						send('attack_start', {
							id: attack.id,
							name: attack.name,
							category: attack.category
						});
					},
					onAttackComplete: (attack, result) => {
						completed++;
						send('attack_complete', {
							id: attack.id,
							name: attack.name,
							breached: result.breached,
							summary: result.summary,
							progress: Math.round((completed / total) * 100),
							completed,
							total
						});
					},
					onVulnerabilityFound: (vuln) => {
						breaches.push(vuln);
						send('breach_found', {
							id: vuln.id,
							title: vuln.title,
							category: vuln.category,
							severity: vuln.severity,
							totalBreaches: breaches.length
						});
					},
					onProgress: (done, totalAttacks) => {
						send('progress', {
							completed: done,
							total: totalAttacks,
							percent: Math.round((done / totalAttacks) * 100)
						});
					}
				}
			);

			try {
				send('scan_start', { total, targetUrl });

				const report = await engine.run(ALL_ATTACKS, {
					targetUrl,
					anonKey,
					serviceKey: ''
				});

				send('scan_complete', {
					stats: report.stats,
					duration: report.duration,
					vulnerabilities: report.vulnerabilities.length
				});
			} catch (error) {
				send('error', {
					message: error instanceof Error ? error.message : 'Scan failed'
				});
			} finally {
				controller.close();
			}
		}
	});

	return new Response(stream, {
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache',
			'Connection': 'keep-alive'
		}
	});
};
