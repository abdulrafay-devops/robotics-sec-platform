/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        'ot-red':    '#ef4444',
        'it-blue':   '#3b82f6',
        'dmz-teal':  '#14b8a6',
        'ai-amber':  '#f59e0b',
        'safe-green':'#10b981',
        'bg-dark':   '#080c14',
        'bg-card':   '#0d1420',
        'bg-panel':  '#111827',
        'border-dim':'#1f2937',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'flow': 'flow 2s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        flow: {
          '0%':   { strokeDashoffset: '24' },
          '100%': { strokeDashoffset: '0' },
        },
        glow: {
          '0%':   { boxShadow: '0 0 4px rgba(16,185,129,0.3)' },
          '100%': { boxShadow: '0 0 12px rgba(16,185,129,0.8)' },
        },
      },
    },
  },
  plugins: [],
}
