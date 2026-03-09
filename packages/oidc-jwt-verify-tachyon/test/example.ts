import {type CertRecords, isRawJwtToken, type RawJwtToken, setTokenCache, useCache} from '@luolapeikko/oidc-jwt-verify';
import {buildTokenCacheBufferSerializer, certCacheBufferSerializer, TachyonCertCache} from '@luolapeikko/oidc-jwt-verify-tachyon';
import type { StandardSchemaV1 } from '@standard-schema/spec';
import {CryptoBufferProcessor, FileStorageDriver} from 'tachyon-drive-node-fs';
import {TachyonExpireCache} from 'tachyon-expire-cache';
import {z} from 'zod';

const tokenBodySchema = z.object({}).loose(); // or build token payload schema
const tokenCacheMapSchema = z.map(z.string().refine(isRawJwtToken), z.object({expires: z.number(), data: tokenBodySchema}));
const bufferSerializer = buildTokenCacheBufferSerializer(tokenCacheMapSchema);
// const stringSerializer = buildTokenCacheStringSerializer<TokenPayload>(tokenCacheMapSchema); // if using string based Tachyon drivers
const processor = new CryptoBufferProcessor(Buffer.from('some-secret-key'));
const driver = new FileStorageDriver({name: 'TokenStorageDriver', fileName: './tokenCache.aes'}, bufferSerializer, processor);
const cache = new TachyonExpireCache<z.infer<typeof tokenBodySchema>, RawJwtToken>({name: 'TachyonExpireCache'}, driver);
setTokenCache(cache);


const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;

// with Tachyon file storage driver
await useCache(new TachyonCertCache(new FileStorageDriver({name: 'FileCertCacheDriver', fileName: './unitTestCache.json'}, certCacheBufferSerializer(certCacheSchema))));