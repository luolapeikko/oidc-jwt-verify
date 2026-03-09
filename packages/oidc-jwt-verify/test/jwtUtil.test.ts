process.env.NODE_ENV = 'testing';

import fs from 'node:fs';
import type {StandardSchemaV1} from '@standard-schema/spec';
import {JsonWebTokenError, type Jwt, type JwtHeader, type JwtPayload, decode as jwtDecode, sign as jwtSign} from 'jsonwebtoken';
import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import {z} from 'zod';
import {
	buildCertFrame,
	type CertRecords,
	FileCertCache,
	IssuerCertLoader,
	isRawJwtToken,
	JwtHeaderError,
	jwtBearerVerify,
	jwtDeleteKid,
	jwtHaveIssuer,
	jwtVerify,
	jwtVerifyPromise,
	setCertLoader,
	testGetCache,
	useCache,
} from '../src';
import {getAzureAccessToken} from './lib/azure';
import {getGoogleIdToken} from './lib/google';
import {signPayload, startExpress, stopExpress} from './lib/localOidc';

let GOOGLE_ID_TOKEN: string | undefined;
let AZURE_ACCESS_TOKEN: string | undefined;
let icl: IssuerCertLoader;

const tokenBodySchema = z.object({}).loose(); // or build token payload schema
const tokenCacheMapSchema = z.map(z.string().refine(isRawJwtToken), z.object({expires: z.number(), data: tokenBodySchema}));

const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;

let fileCertCache: FileCertCache;

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

const certBased = signPayload({hello: 'world'}, {kid: 'forCert', issuer: 'http://localhost:7836', audience: 'test_audience', expiresIn: '1h', subject: 'test_subject'});
const modExpBased = signPayload({hello: 'world'}, {kid: 'fromExponent', issuer: 'http://localhost:7836', audience: 'test_audience', expiresIn: '1h', subject: 'test_subject'});

describe('jwtUtil', () => {
	beforeAll(async () => {
		await startExpress(7836);
		[AZURE_ACCESS_TOKEN, GOOGLE_ID_TOKEN] = await Promise.all([getAzureAccessToken(), getGoogleIdToken()]);
	});
	describe('jwtVerifyPromise', () => {
		it('should fail internal jwtVerifyPromise with broken data', async () => {
			await expect(jwtVerifyPromise('qwe', 'qwe')).rejects.toEqual(new JsonWebTokenError('jwt malformed'));
		});
	});
	describe('jwtVerify', () => {
		it('should fail if broken token format', async () => {
			await expect(jwtVerify('asd')).rejects.toEqual(new JwtHeaderError('Not JWT token string format'));
		});
		it('should fail if broken token', async () => {
			await expect(jwtVerify('asd.asd.asd')).rejects.toEqual(new JwtHeaderError("token header: Can't decode token"));
		});
		it('should fail is issuer url is missing', async () => {
			const test = jwtSign({}, 'test');
			await expect(jwtVerify(test)).rejects.toEqual(new JwtHeaderError('token header: missing issuer parameter'));
		});
		it('should fail is kid is missing', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(test)).rejects.toEqual(new JwtHeaderError('token header: missing kid parameter'));
		});
		it('should fail if auth type is not Bearer', async () => {
			const test = jwtSign({}, 'test', {issuer: 'https://accounts.google.com'});
			await expect(jwtVerify(`Basic ${test}`)).rejects.toEqual(new JwtHeaderError('token header: wrong authentication header type'));
		});
		it('should not load issuer certs if not allowed', async () => {
			expect(jwtHaveIssuer('http://localhost:7836')).to.be.eq(false);
			await expect(jwtVerify(modExpBased, {issuer: [] as unknown as [string, ...string[]]})).rejects.toEqual(
				new JwtHeaderError('token header: issuer is not valid'),
			);
			expect(jwtHaveIssuer('http://localhost:7836')).to.be.eq(false);
		});
	});
	describe('tokens with FileCertCache', () => {
		beforeAll(async () => {
			await testGetCache().clear();
			setCertLoader(new IssuerCertLoader());
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			fileCertCache = new FileCertCache({
				fileName: './unitTestCache.json',
				pretty: true,
				schema: certCacheSchema,
			});
			fileCertCache.setLogger(undefined);
			await useCache(fileCertCache);
		});
		it('Test ExpMod IdToken', async () => {
			expect(jwtHaveIssuer('http://localhost:7836	')).to.be.eq(false);
			const {body, isCached} = await jwtVerify(modExpBased, {issuer: ['http://localhost:7836']});
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(false);
			expect(jwtHaveIssuer('http://localhost:7836')).to.be.eq(true);
		});
		it('Test ExpMod IdToken cached', async () => {
			const {body, isCached} = await jwtVerify(modExpBased!);
			expect(body).not.to.be.eq(null);
			expect(isCached).to.be.eq(true);
		});
		it('Test jwt cache speed (jwt 100 times)', async () => {
			for (let i = 0; i < 100; i++) {
				await jwtVerify(modExpBased!);
			}
		});
		it('Test ExpMod token as Bearer Token', async () => {
			const {body, isCached} = await jwtBearerVerify<{test?: string}>(`Bearer ${modExpBased}`, {issuer: ['http://localhost:7836']});
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
				await jwtBearerVerify(`Bearer ${modExpBased}`, {issuer: ['not_valid_issuer']});
				throw new Error("should not happen as we don't have parameters");
			} catch (_err) {
				// ok
			}
		});
		it('Test delete kid and check force reload', async () => {
			const decoded = jwtDecode(modExpBased!, {complete: true});
			isAsymmetricJwt(decoded);
			jwtDeleteKid(decoded.payload.iss, decoded.header.kid);
			jwtDeleteKid('test', decoded.header.kid);
			const decode = await jwtBearerVerify(`Bearer ${modExpBased}`, {issuer: ['http://localhost:7836']});
			expect(decode).not.to.be.eq(null);
		});
		it('test Azure ID Token ', {skip: !AZURE_ACCESS_TOKEN}, async () => {
			const decode = await jwtVerify(`Bearer ${AZURE_ACCESS_TOKEN}`);
			expect(decode).not.to.be.eq(null);
		});
		it('test Cert based ID Token', async () => {
			const decode = await jwtVerify(`Bearer ${certBased}`);
			expect(decode).not.to.be.eq(null);
		});
		it('test Mod/Exp based ID Token', async () => {
			const decode = await jwtVerify(`Bearer ${modExpBased}`);
			expect(decode).not.to.be.eq(null);
		});
		afterAll(async () => {
			if (fs.existsSync('./unitTestCache.json')) {
				await fs.promises.unlink('./unitTestCache.json');
			}
			fileCertCache.close();
		});
	});
	describe('test IssuerCertLoader', () => {
		beforeAll(() => {
			icl = new IssuerCertLoader();
		});
		it('should throw if issuer is not found (hostname error)', async () => {
			await expect(icl.getCert('https://123qweasdqwe123zzz/uuaaakkk/', 'unknown')).rejects.toEqual(
				new Error('pullIssuerCerts https://123qweasdqwe123zzz/uuaaakkk/ fetch failed'),
			);
		});
		it('should throw if issuer is not found (json error)', async () => {
			await expect(icl.getCert('https://google.com', 'unknown')).rejects.toEqual(new Error('pullIssuerCerts https://google.com fetch error: Not Found'));
		});
		it('should throw when get cert for unknown kid ', async () => {
			await expect(icl.getCert('https://accounts.google.com', 'unknown')).rejects.toEqual(
				new Error("no key Id 'unknown' found for issuer 'https://accounts.google.com'"),
			);
		});
	});
	describe('test buildCertFrame', () => {
		it('should get RSA PUBLIC key structure as Buffer', () => {
			const data = Buffer.from(
				'MIIBCgKCAQEA18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf//7pVEVJJyDuL5a8PARRYQtH68w+0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M/8pJ6qiOjvjF9bhEq0CC/f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9/NdCUuCsdqavd4T+VWnbplbB8YsC+R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE+nCIDwIDAQAB',
			);
			expect(buildCertFrame(data)).to.be.a.instanceof(Buffer);
		});
		it('should fail if not correct Buffer', () => {
			expect(buildCertFrame.bind(null, Buffer.from(''))).to.be.throw('Cert data error');
		});
		it('should get secret key as string', () => {
			const data = 'secretKey';
			expect(buildCertFrame(data)).to.be.a('string');
		});
	});
	afterAll(async () => {
		await stopExpress();
	});
});
