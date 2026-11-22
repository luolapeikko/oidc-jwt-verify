# @luolapeikko/oidc-jwt-verify

[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
[![npm version](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify.svg)](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify)
[![Maintainability](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/maintainability.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![Code Coverage](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/coverage.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![CI/CD](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify.yml/badge.svg)](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify.yml)

## JSON Web Token utility for validating OpenID JWT tokens against issuer public SSL keys

- Can build public PEM certificates from a modulus and exponent (for example, Google OIDC)
- Caches issuer OpenID Connect configuration for 24 hours
- A new token `kid` forces reloading of the OpenID Connect `jwks_uri` data
- When issuers are specified, certificate fetching is also limited to those issuers

### Disclaimer

- This validates **ANY** OpenID Connect JWT token against the issuer's public SSL keys unless the specified issuers restrict validation.
- When using JWT verification in authentication flows, restrict the issuers and audiences or validate and handle the token payload, including its issuer, for authorization (for example, in multi-tenant application scenarios).

## Usage example

```typescript
// with Bearer header
try {
	const { body, isCached } = await jwtBearerVerify(req.headers.authorization, {
		issuer: ["https://accounts.google.com"],
		audience: ["0000000000.apps.googleusercontent.com"],
	});
} catch (err) {
	console.log(err);
}
// Or token only
try {
	const { body, isCached } = await jwtVerify(process.env.GOOGLE_ID_TOKEN, {
		issuer: ["https://accounts.google.com"],
		audience: ["0000000000.apps.googleusercontent.com"],
	});
} catch (err) {
	console.log(err);
}

// attach logger to see http requests (console and log4js should be working)
setJwtLogger(console);
```

## Enable public cert file caching

```typescript
const certCacheSchema = z.object({
	certs: z.record(z.string(), z.record(z.string(), z.string())),
	_ts: z.number(),
}) satisfies StandardSchemaV1<unknown, CertRecords>;
await useCache(
	new FileCertCache({ fileName: "./certCache.json", schema: certCacheSchema }),
);

// or with Tachyon storage driver
await useCache(
	new TachyonCertCache(
		new FileStorageDriver(
			{ name: "FileCertCacheDriver", fileName: "./unitTestCache.json" },
			certCacheBufferSerializer(certCacheSchema),
		),
	),
);
```

## Enable verified token persist caching (Tachyon storage driver with encryption)

```typescript
import {
	isRawJwtToken,
	type RawJwtToken,
	setTokenCache,
} from "@luolapeikko/oidc-jwt-verify";
import { buildTokenCacheBufferSerializer } from "@luolapeikko/oidc-jwt-verify-tachyon";
import {
	CryptoBufferProcessor,
	FileStorageDriver,
} from "tachyon-drive-node-fs";
import { TachyonExpireCache } from "tachyon-expire-cache";
import { z } from "zod";

const tokenBodySchema = z.object({}).loose(); // or build token payload schema
const tokenCacheMapSchema = z.map(
	z.string().refine(isRawJwtToken),
	z.object({ expires: z.number(), data: tokenBodySchema }),
);
const bufferSerializer = buildTokenCacheBufferSerializer(tokenCacheMapSchema);
// const stringSerializer = buildTokenCacheStringSerializer(tokenCacheMapSchema); // if using string based Tachyon drivers
const processor = new CryptoBufferProcessor(Buffer.from("some-secret-key"));
const driver = new FileStorageDriver(
	{ name: "TokenStorageDriver", fileName: "./tokenCache.aes" },
	bufferSerializer,
	processor,
);
const cache = new TachyonExpireCache<
	z.infer<typeof tokenBodySchema>,
	RawJwtToken
>({ name: "TachyonExpireCache" }, driver);
setTokenCache(cache);
```
