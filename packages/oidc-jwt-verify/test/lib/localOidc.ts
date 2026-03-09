import type {Server} from 'node:http';
import Express, {type Application} from 'express';
import type {JwtPayload, SignOptions} from 'jsonwebtoken';
import {sign as jwtSign} from 'jsonwebtoken';
import {asn1, md, pki, util} from 'node-forge';

const KEY_IDS = {
	forCert: 'local-cert-kid',
	fromExponent: 'local-exp-mod-kid',
} as const;

type LocalKid = keyof typeof KEY_IDS;

const keyPairs = {
	forCert: pki.rsa.generateKeyPair(2048),
	fromExponent: pki.rsa.generateKeyPair(2048),
} as const;

const privateKeysPem = {
	forCert: pki.privateKeyToPem(keyPairs.forCert.privateKey),
	fromExponent: pki.privateKeyToPem(keyPairs.fromExponent.privateKey),
} as const;

const certX5c = createSelfSignedCertX5c(keyPairs.forCert.privateKey, keyPairs.forCert.publicKey);

const app = Express();
let server: Server | undefined;
let issuerUrl = '';

app.use(Express.json());

app.get('/.well-known/openid-configuration', (_req, res) => {
	res.status(200).json({
		issuer: issuerUrl,
		jwks_uri: `${issuerUrl}/keys`,
	});
});

app.get('/keys', (_req, res) => {
	res.status(200).json(buildJwks());
});

export function startExpress(port: string | number): Promise<Application> {
	return new Promise((resolve) => {
		server = app.listen(port, () => {
			const serverAddress = server?.address();
			if (typeof serverAddress === 'object' && serverAddress) {
				issuerUrl = `http://127.0.0.1:${serverAddress.port}`;
			} else {
				issuerUrl = `http://127.0.0.1:${String(port)}`;
			}
			resolve(app);
		});
	});
}

export function stopExpress(): Promise<void> {
	return new Promise((resolve, reject) => {
		if (!server) {
			reject(new Error('no express instance found'));
			return;
		}
		server.close(() => {
			server = undefined;
			issuerUrl = '';
			resolve();
		});
	});
}

export function getLocalIssuerUrl(): string {
	if (!issuerUrl) {
		throw new Error('local oidc server is not started');
	}
	return issuerUrl;
}

export function getLocalKids() {
	return {...KEY_IDS};
}

export function signPayload(
	payload: string | Buffer | object,
	{kid = 'forCert', issuer = issuerUrl || 'http://127.0.0.1:0', ...options}: SignOptions & {kid?: LocalKid; issuer?: string} = {},
): string {
	return jwtSign(payload as string | Buffer | JwtPayload, privateKeysPem[kid], {
		algorithm: 'RS256',
		issuer,
		keyid: KEY_IDS[kid],
		...options,
	});
}

function createSelfSignedCertX5c(privateKey: pki.rsa.PrivateKey, publicKey: pki.rsa.PublicKey): string {
	const cert = pki.createCertificate();
	cert.publicKey = publicKey;
	cert.serialNumber = '01';
	cert.validity.notBefore = new Date(Date.now() - 60_000);
	cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

	const attrs = [{name: 'commonName', value: 'local-oidc-test'}];
	cert.setSubject(attrs);
	cert.setIssuer(attrs);
	cert.sign(privateKey, md.sha256.create());

	const der = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
	return util.encode64(der);
}

function buildJwks() {
	return {
		keys: [
			{
				kid: KEY_IDS.forCert,
				kty: 'RSA',
				use: 'sig',
				alg: 'RS256',
				x5c: [certX5c],
			},
			{
				kid: KEY_IDS.fromExponent,
				kty: 'RSA',
				use: 'sig',
				alg: 'RS256',
				n: toBase64UrlFromHex(keyPairs.fromExponent.publicKey.n.toString(16)),
				e: toBase64UrlFromHex(keyPairs.fromExponent.publicKey.e.toString(16)),
			},
		],
	};
}

function toBase64UrlFromHex(hex: string): string {
	const normalized = hex.length % 2 === 0 ? hex : `0${hex}`;
	const value = Buffer.from(normalized, 'hex').toString('base64');
	return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
