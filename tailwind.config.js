/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	theme: {
		extend: {
			colors: {
				// SupaRalph Design System - Supabase Green
				supa: {
					50: '#ecfdf5',
					100: '#d1fae5',
					200: '#a7f3d0',
					300: '#6ee7b7',
					400: '#3ECF8E',  // Supabase signature green
					500: '#34b87a',
					600: '#2a9d6a',
					700: '#21845a',
					800: '#186b4a',
					900: '#14533b',
				},
				// Alias for backwards compat
				vibe: {
					50: '#ecfdf5',
					100: '#d1fae5',
					200: '#a7f3d0',
					300: '#6ee7b7',
					400: '#3ECF8E',
					500: '#34b87a',
					600: '#2a9d6a',
					700: '#21845a',
					800: '#186b4a',
					900: '#14533b',
				},
				// SupaShield brand colors
				shield: {
					50: '#f0fdf4',
					100: '#dcfce7',
					200: '#bbf7d0',
					300: '#86efac',
					400: '#4ade80',
					500: '#22c55e',
					600: '#16a34a',
					700: '#15803d',
					800: '#166534',
					900: '#14532d',
				},
				breach: {
					50: '#fef2f2',
					100: '#fee2e2',
					200: '#fecaca',
					300: '#fca5a5',
					400: '#f87171',
					500: '#ef4444',
					600: '#dc2626',
					700: '#b91c1c',
					800: '#991b1b',
					900: '#7f1d1d',
				},
				secure: {
					50: '#f0fdf4',
					100: '#dcfce7',
					500: '#22c55e',
					600: '#16a34a',
				},
				// Dark theme surfaces
				surface: {
					900: '#0a0a0a',
					800: '#111111',
					700: '#1a1a1a',
					600: '#222222',
					500: '#2a2a2a',
				}
			},
			fontFamily: {
				mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
			},
			animation: {
				'float': 'float 6s ease-in-out infinite',
				'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
				'slide-up': 'slide-up 0.8s ease-out',
				'slide-in-left': 'slide-in-left 0.6s ease-out',
				'slide-in-right': 'slide-in-right 0.6s ease-out',
				'fade-in': 'fade-in 1s ease-out',
				'danger-pulse': 'danger-pulse 1.5s ease-in-out infinite',
				'scan-line': 'scan-line 2s linear infinite',
				'scan-line-vertical': 'scan-line-vertical 2.5s linear infinite',
				'glitch': 'glitch 0.3s ease-in-out infinite',
				'typing': 'typing 3.5s steps(40, end)',
				'blink': 'blink 1s step-end infinite',
				// Laser animations
				'laser-horizontal': 'laser-horizontal 3s linear infinite',
				'laser-horizontal-reverse': 'laser-horizontal-reverse 3.5s linear infinite',
				'laser-vertical': 'laser-vertical 4s linear infinite',
				'laser-vertical-reverse': 'laser-vertical-reverse 3.5s linear infinite',
				'laser-diagonal': 'laser-diagonal 5s linear infinite',
				'laser-diagonal-reverse': 'laser-diagonal-reverse 6s linear infinite',
			},
			keyframes: {
				float: {
					'0%, 100%': { transform: 'translateY(0px)' },
					'50%': { transform: 'translateY(-20px)' },
				},
				'pulse-glow': {
					'0%, 100%': { boxShadow: '0 0 20px rgba(239, 68, 68, 0.3)' },
					'50%': { boxShadow: '0 0 40px rgba(239, 68, 68, 0.6)' },
				},
				'slide-up': {
					'0%': { transform: 'translateY(50px)', opacity: '0' },
					'100%': { transform: 'translateY(0)', opacity: '1' },
				},
				'slide-in-left': {
					'0%': { transform: 'translateX(-100px)', opacity: '0' },
					'100%': { transform: 'translateX(0)', opacity: '1' },
				},
				'slide-in-right': {
					'0%': { transform: 'translateX(100px)', opacity: '0' },
					'100%': { transform: 'translateX(0)', opacity: '1' },
				},
				'fade-in': {
					'0%': { opacity: '0' },
					'100%': { opacity: '1' },
				},
				'danger-pulse': {
					'0%, 100%': {
						borderColor: 'rgba(239, 68, 68, 0.5)',
						boxShadow: '0 0 10px rgba(239, 68, 68, 0.2)'
					},
					'50%': {
						borderColor: 'rgba(239, 68, 68, 1)',
						boxShadow: '0 0 30px rgba(239, 68, 68, 0.5)'
					},
				},
				'scan-line': {
					'0%': { transform: 'translateY(-100%)' },
					'100%': { transform: 'translateY(100%)' },
				},
				glitch: {
					'0%, 100%': { transform: 'translate(0)' },
					'20%': { transform: 'translate(-2px, 2px)' },
					'40%': { transform: 'translate(-2px, -2px)' },
					'60%': { transform: 'translate(2px, 2px)' },
					'80%': { transform: 'translate(2px, -2px)' },
				},
				typing: {
					'from': { width: '0' },
					'to': { width: '100%' },
				},
				blink: {
					'50%': { borderColor: 'transparent' },
				},
				// Laser keyframes
				'scan-line-vertical': {
					'0%': { transform: 'translateX(-100%)' },
					'100%': { transform: 'translateX(400%)' },
				},
				'laser-horizontal': {
					'0%': { transform: 'translateX(-100%)' },
					'100%': { transform: 'translateX(calc(100vw + 100%))' },
				},
				'laser-horizontal-reverse': {
					'0%': { transform: 'translateX(100vw)' },
					'100%': { transform: 'translateX(-100%)' },
				},
				'laser-vertical': {
					'0%': { transform: 'translateY(-100%)' },
					'100%': { transform: 'translateY(100vh)' },
				},
				'laser-vertical-reverse': {
					'0%': { transform: 'translateY(100vh)' },
					'100%': { transform: 'translateY(-100%)' },
				},
				'laser-diagonal': {
					'0%': { transform: 'translateX(-50%) translateY(-50%)' },
					'100%': { transform: 'translateX(100vw) translateY(100vh)' },
				},
				'laser-diagonal-reverse': {
					'0%': { transform: 'translateX(100vw) translateY(-50%)' },
					'100%': { transform: 'translateX(-50%) translateY(100vh)' },
				},
			},
			// Vibeship: No rounded corners
			borderRadius: {
				'none': '0',
				'sm': '0',
				'DEFAULT': '0',
				'md': '0',
				'lg': '0',
				'xl': '0',
				'2xl': '0',
				'3xl': '0',
				'full': '0',
			}
		}
	},
	plugins: []
};
