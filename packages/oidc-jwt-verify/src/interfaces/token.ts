import type * as jwt from 'jsonwebtoken';

export type RawJwtToken = `${string}.${string}.${string}`;

export function isRawJwtToken(token: unknown): token is RawJwtToken {
	return typeof token === 'string' && token.split('.').length === 3;
}

export type FullDecodedIssuerTokenStructure = {
	header: jwt.JwtHeader & {kid: string};
	payload: jwt.JwtPayload & {iss: string};
};
