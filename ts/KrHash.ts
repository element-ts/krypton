import * as Crypto from "crypto";

export enum KrHashAlgorithm {
	sha256 = "sha256",
	sha512 = "sha512",
	md5 = "md5"
}

export class KrHash {

	private readonly hasher: Crypto.Hash;

	public constructor(algorithm: KrHashAlgorithm = KrHashAlgorithm.sha512) {

		this.hasher = Crypto.createHash(algorithm);

	}

	public append(data: Buffer): void {

		this.hasher.update(data);

	}

	public hash(): Buffer {

		return this.hasher.digest();

	}

	public static hash(data: Buffer, algorithm: KrHashAlgorithm = KrHashAlgorithm.sha512): Buffer {

		const hasher: KrHash = new KrHash(algorithm);
		hasher.append(data);

		return hasher.hash();

	}

}