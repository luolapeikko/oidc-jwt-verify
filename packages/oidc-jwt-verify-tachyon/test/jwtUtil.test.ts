process.env.NODE_ENV = 'testing';

import fs from 'node:fs';
import {
	type CertRecords,
	IssuerCertLoader,
	isRawJwtToken,
	jwtBearerVerify,
	jwtDeleteKid,
	jwtHaveIssuer,
	jwtVerify,
	type RawJwtToken,
	setCertLoader,
	setTokenCache,
	type TokenPayload,
	testGetCache,
	useCache,
} from '@luolapeikko/oidc-jwt-verify';
import type {StandardSchemaV1} from '@standard-schema/spec';
import {type Jwt, type JwtHeader, type JwtPayload, decode as jwtDecode, sign as jwtSign} from 'jsonwebtoken';
import {MemoryStorageDriver} from 'tachyon-drive';
import {CryptoBufferProcessor, FileStorageDriver} from 'tachyon-drive-node-fs';
import {TachyonExpireCache} from 'tachyon-expire-cache';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {z} from 'zod';
import {buildTokenCacheBufferSerializer, certCacheBufferSerializer, certCacheStringSerializer, TachyonCertCache} from '../src';
import {getAzureAccessToken} from './lib/azure';
import {getGoogleIdToken} from './lib/google';

let GOOGLE_ID_TOKEN: string;
let AZURE_ACCESS_TOKEN: string;

const tokenBodySchema = z.object({}).loose(); // or build token payload schema
const tokenCacheMapSchema = z.map(z.string().refine(isRawJwtToken), z.object({expires: z.number(), data: tokenBodySchema}));
const bufferSerializer = buildTokenCacheBufferSerializer(tokenCacheMapSchema);
const processor = new CryptoBufferProcessor(Buffer.from('some-secret-key'));
const driver = new FileStorageDriver({name: 'TokenStorageDriver', fileName: './tokenCache.aes'}, bufferSerializer, processor);
const cache = new TachyonExpireCache<z.infer<typeof tokenBodySchema>, RawJwtToken>({name: 'TachyonExpireCache'}, driver);

const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;

type AsymmetricJwt = {
	header: JwtHeader & {kid: string};
	payload: JwtPayload & {iss: string};
	signature: string;
};

function isAsymmetricJwt(data: Jwt | undefined | null): asserts data is AsymmetricJwt {
	if (!data) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('header' in data && 'payload' in data && 'signature' in data)) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!data?.payload || typeof data.payload !== 'object') {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('kid' in data.header)) {
		throw Error('not valid AsymmetricJwt');
	}
	if (!('iss' in data.payload)) {
		throw Error('not valid AsymmetricJwt');
	}
}

describe('jwtUtil', () => {
	beforeAll(async () => {
		[AZURE_ACCESS_TOKEN, GOOGLE_ID_TOKEN] = await Promise.all([getAzureAccessToken(), getGoogleIdToken()]);
	});
	describe('tokens with TachyonCertCache', () => {
		beforeAll(async () => {
			await driver.clear(); // clear token cache
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			setTokenCache(cache);
			await useCache(
				new TachyonCertCache(
					new FileStorageDriver({name: 'FileCertCacheDriver', fileName: './unitTestCache.json'}, certCacheBufferSerializer(certCacheSchema)),
				),
			);
		});
		it('Test Google IdToken', async () => {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>({name: 'TachyonExpireCache'}, driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async () => {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(undefined);
			expect(body.aud).not.to.be.eq(undefined);
			expect(body.exp).not.to.be.eq(undefined);
			expect(body.iat).not.to.be.eq(undefined);
			expect(body.iss).not.to.be.eq(undefined);
			expect(body.sub).not.to.be.eq(undefined);
			expect(body.test).to.be.eq(undefined);
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwtSign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async () => {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		afterAll(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
		});
	});
	describe('tokens with TachyonCertCache in memory', () => {
		beforeAll(async () => {
			await cache.clear();
			await driver.clear(); // clear token cache
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			await useCache(new TachyonCertCache(new MemoryStorageDriver({name: 'MemoryCertCacheDriver'}, certCacheStringSerializer(certCacheSchema), null)));
		});
		it('Test Google IdToken', async () => {
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('https://accounts.google.com')).to.be.eq(true);
		});
		it('Test Google IdToken cached', async () => {
			setTokenCache(new TachyonExpireCache<TokenPayload, RawJwtToken>({name: 'TachyonExpireCache'}, driver)); // rebuild new cache
			const {body, isCached} = await jwtVerify(GOOGLE_ID_TOKEN);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async () => {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(GOOGLE_ID_TOKEN);
			}
		});
		it('Test Google token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['https://accounts.google.com']});
			expect(body).not.to.be.eq(undefined);
			expect(body.aud).not.to.be.eq(undefined);
			expect(body.exp).not.to.be.eq(undefined);
			expect(body.iat).not.to.be.eq(undefined);
			expect(body.iss).not.to.be.eq(undefined);
			expect(body.sub).not.to.be.eq(undefined);
			expect(body.test).to.be.eq(undefined);
			expect(isCached).to.be.eq(true);
		});
		it('Test non Bearer auth', async () => {
			try {
				await jwtBearerVerify('Basic some:fun');
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non issuer token ', async () => {
			const test = jwtSign({test: 'asd'}, 'secret');
			try {
				await jwtVerify(test);
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test non-valid issuer', async () => {
			try {
				await jwtBearerVerify(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(GOOGLE_ID_TOKEN, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify(`Bearer ${GOOGLE_ID_TOKEN}`, {issuer: ['https://accounts.google.com']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', async () => {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
	});
	afterAll(async () => {
		await driver.clear();
	});
});
