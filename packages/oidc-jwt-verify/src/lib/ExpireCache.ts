export interface IExpireCache<T> {
	get(key: string): T | undefined;
	set(key: string, value: T, ttl?: Date): void;
	delete(key: string): void;
	clear(): void;
}

export interface IExpireAsyncCache<T> {
	get(key: string): Promise<T | undefined>;
	set(key: string, value: T, ttl?: Date): Promise<void>;
	delete(key: string): Promise<void>;
	clear(): Promise<void>;
}

export class ExpireCache<T extends object> extends Map<string, T> implements IExpireCache<T> {
	#ttl = new Map<string, number>();
	#defaultTtl?: number;

	public constructor(ttl?: number) {
		super();
		this.#defaultTtl = ttl;
	}

	public get(key: string): T | undefined {
		const ttl = this.#ttl.get(key);
		if (ttl !== undefined && ttl < Date.now()) {
			this.#ttl.delete(key);
			super.delete(key);
			return undefined;
		}
		return super.get(key);
	}

	public set(key: string, value: T, ttl?: Date): this {
		super.set(key, value);
		const ttlValue = ttl?.getTime() ?? (this.#defaultTtl ? Date.now() + this.#defaultTtl : undefined);
		if (ttlValue !== undefined) {
			this.#ttl.set(key, ttlValue);
		}
		return this;
	}

	public delete(key: string): boolean {
		this.#ttl.delete(key);
		return super.delete(key);
	}
	public clear(): void {
		this.#ttl.clear();
		super.clear();
	}
}
