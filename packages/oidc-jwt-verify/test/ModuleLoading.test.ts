/** biome-ignore-all lint/style/noCommonJs: module load testing */
import {sign} from 'jsonwebtoken';
import {describe, expect, it} from 'vitest';

describe('@luolapeikko/oidc-jwt-verify', () => {
	describe('CJS Module loading', () => {
		it('test CJS loading', () => {
			const {CertCache} = require('@luolapeikko/oidc-jwt-verify');
			expect(CertCache).toBeInstanceOf(Object);
		});
		it('test CJS jwtVerifyPromise', () => {
			const {jwtVerifyPromise} = require('@luolapeikko/oidc-jwt-verify');
			expect(jwtVerifyPromise).toBeInstanceOf(Function);
			const privateKey = 'some-private-key';
			const token = sign({foo: 'bar'}, privateKey);
			expect(jwtVerifyPromise(token, privateKey)).resolves.toBeDefined();
		});
	});
	describe('ESM Module loading', () => {
		it('test ESM loading', async () => {
			const {CertCache} = await import('@luolapeikko/oidc-jwt-verify');
			expect(CertCache).toBeInstanceOf(Object);
		});
		it('test ESM jwtVerifyPromise', async () => {
			const {jwtVerifyPromise} = await import('@luolapeikko/oidc-jwt-verify');
			expect(jwtVerifyPromise).toBeInstanceOf(Function);
			const privateKey = 'some-private-key';
			const token = sign({foo: 'bar'}, privateKey);
			await expect(jwtVerifyPromise(token, privateKey)).resolves.toBeDefined();
		});
	});
});
