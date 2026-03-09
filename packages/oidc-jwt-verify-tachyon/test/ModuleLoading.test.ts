/** biome-ignore-all lint/style/noCommonJs: module load testing */
import {describe, expect, it} from 'vitest';

describe('@luolapeikko/oidc-jwt-verify-tachyon', () => {
	it('test CJS loading', () => {
		const {TachyonCertCache} = require('@luolapeikko/oidc-jwt-verify-tachyon');
		expect(TachyonCertCache).toBeInstanceOf(Object);
	});
	it('test ESM loading', async () => {
		const {TachyonCertCache} = await import('@luolapeikko/oidc-jwt-verify-tachyon');
		expect(TachyonCertCache).toBeInstanceOf(Object);
	});
});
