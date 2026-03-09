import * as jwt from 'jsonwebtoken';
import type {TokenPayload} from '../interfaces/token';

type JwtVerifyPromiseFunc<T = Record<string, unknown>> = (...params: Parameters<typeof jwt.verify>) => Promise<TokenPayload<T> | undefined>;


/**
 * Jwt validate Promise wrapper for jwt.verify function
 * @throws `JsonWebTokenError` if token is invalid
 * @throws `TokenExpiredError` if token is expired
 * @throws `NotBeforeError` if current time is before the nbf claim
 * @param token JWT token string to verify
 * @param secretOrPublicKey Secret or public key for verifying the token
 * @param options Optional jwt verify options
 * @returns Promise that resolves with the decoded token payload if verification is successful, or rejects with an error if verification fails
 * @example
 * const decoded = await jwtVerifyPromise(token, secretOrPublicKey, options);
 * console.log(decoded); // decoded token payload
 */
export const jwtVerifyPromise: JwtVerifyPromiseFunc = (token, secretOrPublicKey, options?) => {
	return new Promise<TokenPayload | undefined>((resolve, reject) => {
		jwt.verify(token, secretOrPublicKey, options, (err: jwt.VerifyErrors | null, decoded: object | string | undefined) => {
			if (err) {
				reject(err);
			} else {
				if (typeof decoded === 'string') {
					resolve(undefined);
				} else {
					resolve(decoded);
				}
			}
		});
	});
};
