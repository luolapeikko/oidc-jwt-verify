import {defineConfig} from 'tsdown';

export default defineConfig({
    entry: ['./src/index.ts'],
	format: {
		esm: {
			target: ['es2020'],
		},
		cjs: {
			target: ['node20'],
		},
	},
	dts: true,
	deps: {
        onlyBundle: ['@luolapeikko/logger-type', '@standard-schema/spec'],
    },
});
