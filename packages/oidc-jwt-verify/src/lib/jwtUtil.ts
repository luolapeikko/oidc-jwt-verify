import {type JwtPayload, type VerifyErrors, verify} from 'jsonwebtoken';

export type JwtVerifyPromiseFunc = (...params: Parameters<typeof verify>) => Promise<JwtPayload>;

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
	return new Promise<JwtPayload>((resolve, reject) =>
		verify(token, secretOrPublicKey, options, (err: VerifyErrors | null, decoded: object | string | undefined) => {
			if (err) {
				reject(err);
			} else {
				if (typeof decoded === 'string') {
					reject(new Error('Jwt Decoded token is a string'));
				} else if (!decoded) {
					reject(new Error('Jwt Decoded token is undefined'));
				} else {
					resolve(decoded);
				}
			}
		}),
	);
};
