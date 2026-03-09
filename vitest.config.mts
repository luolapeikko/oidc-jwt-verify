import tsconfigPaths from 'vite-tsconfig-paths';
import {defineConfig} from 'vitest/config';

export default defineConfig({
	optimizeDeps: {
		include: [],
	},
	plugins: [tsconfigPaths()],
	test: {
		reporters: ['verbose', 'github-actions'],
		coverage: {
			exclude: ['**/dist/**', '**/test/**', '**/*.test-d.ts', '**/index.ts'],
			include: ['packages/**/*.ts'],
			provider: 'v8',
			reporter: ['text', 'lcov'],
		},
		globals: true,
		setupFiles: ['dotenv/config'],
		typecheck: {include: ['**/*.test-d.ts']},
	},
});
