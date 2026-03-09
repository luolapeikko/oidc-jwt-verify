# @luolapeikko/oidc-jwt-verify-tachyon

[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/ellerbrock/typescript-badges/)
[![npm version](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify-tachyon.svg)](https://badge.fury.io/js/@luolapeikko%2Foidc-jwt-verify-tachyon)
[![Maintainability](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/maintainability.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![Code Coverage](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify/coverage.svg)](https://qlty.sh/gh/luolapeikko/projects/oidc-jwt-verify)
[![CI/CD](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify-tachyon.yml/badge.svg)](https://github.com/luolapeikko/oidc-jwt-verify/actions/workflows/oidc-jwt-verify-tachyon.yml)

## Tachyon drivers for @luolapeikko/oidc-jwt-verify caches

- Tachyon storage driver can be used as public ssl cert caching.
- Tachyon storage driver can be used as validated token caching.

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
