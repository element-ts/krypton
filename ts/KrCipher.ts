import * as Crypto from "crypto";

export class KrCipher {

	private readonly salt: Buffer;
	private readonly password: Buffer;
	private static readonly ALGORITHM: string = "aes-192-cbc";

	public constructor(password: Buffer, salt?: Buffer) {

		this.salt = salt ?? Crypto.randomBytes(32);
		this.password = password;

	}

	public encrypt(data: Buffer): Buffer {

		return KrCipher.encrypt(data, this.password, this.salt);

	}

	public decrypt(data: Buffer): Buffer {

		return KrCipher.decrypt(data, this.password, this.salt);

	}

	public static encrypt(data: Buffer, password: Buffer, salt?: Buffer): Buffer {

		const key: Buffer = Crypto.scryptSync(password, salt ?? Buffer.alloc(32, 0), 24);
		const initializationVector: Buffer = Buffer.alloc(16, 0);
		const cipher: Crypto.Cipher = Crypto.createCipheriv(this.ALGORITHM, key, initializationVector);

		return Buffer.concat([cipher.update(data), cipher.final()]);

	}

	public static decrypt(data: Buffer, password: Buffer, salt?: Buffer): Buffer {

		const key: Buffer = Crypto.scryptSync(password, salt ?? Buffer.alloc(32, 0), 24);
		const initializationVector: Buffer = Buffer.alloc(16, 0);
		const cipher: Crypto.Decipher = Crypto.createDecipheriv(this.ALGORITHM, key, initializationVector);

		return Buffer.concat([cipher.update(data), cipher.final()]);

	}

}