# @luolapeikko/oidc-jwt-verify-tachyon

[![Build Status](https://mharj.visualstudio.com/mharj-jwt-util/_apis/build/status/mharj.mharj-jwt-util?branchName=master)](https://mharj.visualstudio.com/mharj-jwt-util/_build/latest?definitionId=3&branchName=master) ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/mharj/mharj-jwt-util/3) [![Maintainability](https://api.codeclimate.com/v1/badges/a60873c223b5bafadb1f/maintainability)](https://codeclimate.com/github/mharj/mharj-jwt-util/maintainability)

## Tachyon drivers for @luolapeikko/oidc-jwt-verify caches

- Can build public PEM cert from modulus + exponent (i.e. Google OIDC)
- Caches issuer OpenID configuration 24h
- New Token "kid" forces reloading jwks_uri data.

Note: if running NodeJS less than 18.0.0 you need to install and use cross-fetch polyfill

## Enable public cert file caching

```typescript
const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;

// with Tachyon file storage driver
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
