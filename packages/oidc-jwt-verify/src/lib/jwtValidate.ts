import type {ILoggerLike} from '@luolapeikko/logger-type';
import jwt from 'jsonwebtoken';
import type {CertCache} from '../cache/CertCache';
import {type FullDecodedIssuerTokenStructure, isRawJwtToken} from '../interfaces/token';
import {ExpireCache, type IExpireAsyncCache, type IExpireCache} from './ExpireCache';
import {IssuerCertLoader} from './issuerCertLoader';
import {JwtHeaderError} from './JwtHeaderError';
import {jwtVerifyPromise} from './jwtUtil';
import {buildCertFrame} from './rsaPublicKeyPem';

const bearerRegex = /^Bearer (.*?)$/i;

/**
 * Default instance of `IssuerCertLoader`.
 */
let certLoaderInstance = new IssuerCertLoader();

/**
 * Cache for resolved token payloads. The default cache is in memory.
 */
let tokenCache: IExpireCache<jwt.JwtPayload> | IExpireAsyncCache<jwt.JwtPayload> = new ExpireCache<jwt.JwtPayload>();
/**
 * Sets up the cache for verified payloads. In production, persisted caches should be encrypted.
 */
export function setTokenCache(cache: IExpireCache<jwt.JwtPayload> | IExpireAsyncCache<jwt.JwtPayload>): void {
	tokenCache = cache;
}

export function setJwtLogger(logger: ILoggerLike): void {
	certLoaderInstance.logger = logger;
}

/**
 * Sets up the cache for public certificates.
 */
export function useCache(cacheFunctions: CertCache): Promise<void> {
	return certLoaderInstance.setCache(cacheFunctions);
}

export function testGetCache(): IExpireCache<jwt.JwtPayload> | IExpireAsyncCache<jwt.JwtPayload> {
	/* istanbul ignore else  */
	if (process.env.NODE_ENV === 'testing') {
		return tokenCache;
	} else {
		throw new Error('only for testing');
	}
}

export function setCertLoader(newIcl: IssuerCertLoader): void {
	/* istanbul ignore else  */
	if (process.env.NODE_ENV === 'testing') {
		certLoaderInstance = newIcl;
	} else {
		throw new Error('only for testing');
	}
}

const algOptions = new Set(['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none'] as const);

function getKeyIdAndSetOptions(decoded: FullDecodedIssuerTokenStructure, options: jwt.VerifyOptions = {}) {
	const {kid, alg, typ} = decoded.header || {};
	if (!kid) {
		throw new JwtHeaderError('token header: missing kid parameter');
	}
	if (typ !== 'JWT') {
		throw new JwtHeaderError(`token header: type "${typ}" is not valid`);
	}
	if (alg && algOptions.has(alg as jwt.Algorithm)) {
		options.algorithms = [alg as jwt.Algorithm];
	}
	return kid;
}

/**
 * Validates a fully decoded token and ensures that its payload contains an `iss` claim.
 * @param decoded Complete JWT decode, including the header
 * @param options JWT verification options
 * @returns The issuer token structure, including `iss`, when issuer restrictions are configured
 */
function haveValidIssuer(decoded: null | jwt.Jwt, options: jwt.VerifyOptions): FullDecodedIssuerTokenStructure {
	if (!decoded) {
		throw new JwtHeaderError(`token header: Can't decode token`);
	}
	if (typeof decoded.payload !== 'object' || typeof decoded.payload.iss !== 'string') {
		throw new JwtHeaderError('token header: missing issuer parameter');
	}
	if (!decoded.header || typeof decoded.header !== 'object' || typeof decoded.header.kid !== 'string') {
		throw new JwtHeaderError('token header: missing kid parameter');
	}
	if (options.issuer) {
		// prevent loading rogue issuers data if not valid issuer
		const allowedIssuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
		if (!allowedIssuers.includes(decoded.payload.iss)) {
			throw new JwtHeaderError('token header: issuer is not valid');
		}
	}
	return decoded as FullDecodedIssuerTokenStructure;
}

/**
 * The response contains the decoded body and indicates whether it was returned from the cache.
 */
export type JwtResponse<T extends object> = {body: T & jwt.JwtPayload; isCached: boolean};
/**
 * Verifies a JWT token against the issuer's public certificates.
 * @throws `JsonWebTokenError` if token is invalid
 * @throws `TokenExpiredError` if token is expired
 * @throws `NotBeforeError` if current time is before the nbf claim
 * @throws `JwtHeaderError` if token is not in JWT format.
 * @param tokenOrBearer JWT token or Bearer string containing the JWT token
 * @param options JWT verification options
 */
export async function jwtVerify<T extends object>(tokenOrBearer: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> {
	if (typeof tokenOrBearer !== 'string') {
		return Promise.reject(new JwtHeaderError('Token is not a string'));
	}
	const token = bearerRegex.test(tokenOrBearer) ? tokenOrBearer.substring(7) : tokenOrBearer;
	if (!isRawJwtToken(token)) {
		return Promise.reject(new JwtHeaderError('token header: Not JWT token string format'));
	}
	const cached = await tokenCache.get(token);
	if (cached) {
		return {body: cached as jwt.JwtPayload & T, isCached: true};
	}
	const decoded = haveValidIssuer(jwt.decode(token, {complete: true}), options);
	const certString = await certLoaderInstance.getCert(decoded.payload.iss, getKeyIdAndSetOptions(decoded, options));
	const verifiedDecode = (await jwtVerifyPromise(token, buildCertFrame(certString), options)) as T & jwt.JwtPayload;
	if (verifiedDecode.exp) {
		await tokenCache.set(token, verifiedDecode, new Date(verifiedDecode.exp * 1000));
	}
	return {body: verifiedDecode, isCached: false};
}

/**
 * Verifies an authentication `Bearer` header against the issuer's public certificates.
 * @throws `JsonWebTokenError` if token is invalid
 * @throws `TokenExpiredError` if token is expired
 * @throws `NotBeforeError` if current time is before the nbf claim
 * @throws `JwtHeaderError` if token is not in JWT format.
 * @param authHeader Raw authentication header with a `Bearer` prefix
 * @param options JWT verification options
 */
export function jwtBearerVerify<T extends object>(authHeader: string, options: jwt.VerifyOptions = {}): Promise<JwtResponse<T>> {
	const match = bearerRegex.exec(authHeader);
	if (!match) {
		return Promise.reject(new JwtHeaderError('No authentication header'));
	}
	return jwtVerify(match[1], options);
}

export function jwtDeleteKid(issuer: string, kid: string): void {
	certLoaderInstance.deleteKid(issuer, kid);
}

export function jwtHaveIssuer(issuer: string): boolean {
	return certLoaderInstance.haveIssuer(issuer);
}
