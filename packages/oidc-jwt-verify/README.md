# @luolapeikko/oidc-jwt-verify

[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
[![npm version](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify.svg)](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify)
[![Maintainability](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/maintainability.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![Code Coverage](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/coverage.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![CI/CD](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify.yml/badge.svg)](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify.yml)

## Json Webtoken Utility to validate OpenID JWT tokens against issuer public ssl keys

- Can build public PEM cert from modulus + exponent (i.e. Google OIDC)
- Caches issuer OpenID Connector configuration 24h
- New Token "kid" forces reloading OpenID Connector jwks_uri data.

Note: if running NodeJS less than 18.0.0 you need to install and use cross-fetch polyfill

## Usage example

```javascript
// with Bearer header
try {
  const { body, isCached } = await jwtBearerVerify(req.headers.authorization);
} catch (err) {
  console.log(err);
}
// or Just token
try {
  const { body, isCached } = await jwtVerify(process.env.GOOGLE_ID_TOKEN);
} catch (err) {
  console.log(err);
}

// attach logger to see http requests (console and log4js should be working)
setJwtLogger(console);
```

## Enable public cert file caching

```javascript
const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;
await useCache(new FileCertCache({fileName: './certCache.json', schema: certCacheSchema}));

// or with Tachyon storage driver
await useCache(new TachyonCertCache(new FileStorageDriver({name: 'FileCertCacheDriver', fileName: './unitTestCache.json'}, certCacheBufferSerializer(certCacheSchema))));
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
// const stringSerializer = buildTokenCacheStringSerializer<TokenPayload>(tokenCacheMapSchema); // if using string based Tachyon drivers
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
