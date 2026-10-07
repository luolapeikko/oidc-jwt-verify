import {describe, expect, it} from 'vitest';
import {ExpireCache} from '../src/lib/ExpireCache';

describe('ExpireCache', () => {
	it('should set and get values correctly', () => {
		const cache = new ExpireCache<{value: string}>();
		cache.set('key1', {value: 'test'}, new Date(Date.now() + 1000));
		expect(cache.get('key1')).toEqual({value: 'test'});
	});
	it('should expire values correctly', async () => {
		const cache = new ExpireCache<{value: string}>();
		cache.set('key2', {value: 'test'}, new Date(Date.now() + 100));
		expect(cache.get('key2')).toEqual({value: 'test'});
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(cache.get('key2')).toBeUndefined();
	});
});
