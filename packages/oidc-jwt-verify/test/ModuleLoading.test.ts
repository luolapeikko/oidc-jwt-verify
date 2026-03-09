/** biome-ignore-all lint/style/noCommonJs: module load testing */
import {describe, expect, it} from 'vitest';

describe('@luolapeikko/oidc-jwt-verify', () => {
	it('test CJS loading', () => {
		const {CertCache} = require('@luolapeikko/oidc-jwt-verify');
		expect(CertCache).toBeInstanceOf(Object);
	});
	it('test ESM loading', async () => {
		const {CertCache} = await import('@luolapeikko/oidc-jwt-verify');
		expect(CertCache).toBeInstanceOf(Object);
	});
});
