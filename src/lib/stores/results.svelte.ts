/**
 * Results Store - Stores breach test results in localStorage
 */

import { browser } from '$app/environment';
import type { BreachReport } from '$lib/types/attacks';

const STORAGE_KEY = 'supashield_results';
const MAX_RESULTS = 50;

// Load results from localStorage
function loadResults(): BreachReport[] {
	if (!browser) return [];
	const stored = localStorage.getItem(STORAGE_KEY);
	if (!stored) return [];
	try {
		return JSON.parse(stored);
	} catch {
		return [];
	}
}

// Reactive state
let results = $state<BreachReport[]>(loadResults());

// Save to localStorage
function saveResults() {
	if (!browser) return;
	// Keep only last MAX_RESULTS
	const toSave = results.slice(0, MAX_RESULTS);
	localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
}

/**
 * Add a new breach report
 */
export function addResult(report: BreachReport): void {
	results = [report, ...results].slice(0, MAX_RESULTS);
	saveResults();
}

/**
 * Get all results
 */
export function getResults(): BreachReport[] {
	return results;
}

/**
 * Get results for a specific project
 */
export function getProjectResults(projectId: string): BreachReport[] {
	return results.filter((r) => r.projectId === projectId);
}

/**
 * Get a specific result by ID
 */
export function getResult(reportId: string): BreachReport | undefined {
	return results.find((r) => r.id === reportId);
}

/**
 * Delete a result
 */
export function deleteResult(reportId: string): boolean {
	const index = results.findIndex((r) => r.id === reportId);
	if (index === -1) return false;
	results = [...results.slice(0, index), ...results.slice(index + 1)];
	saveResults();
	return true;
}

/**
 * Clear all results
 */
export function clearResults(): void {
	results = [];
	saveResults();
}

/**
 * Get latest result for a project
 */
export function getLatestResult(projectId: string): BreachReport | undefined {
	return results.find((r) => r.projectId === projectId);
}

// Export reactive getter
export const resultsStore = {
	get results() {
		return results;
	},
	get count() {
		return results.length;
	}
};
