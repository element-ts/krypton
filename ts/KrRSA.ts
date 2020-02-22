import * as Crypto from "crypto";

export type KrRSAKeyPair = {publicKey: Buffer, privateKey: Buffer};

export class KrRSA {

	public static generateKeys(modulusLength: number = 4096, passphrase: string = ""): KrRSAKeyPair {

		const keys: Crypto.KeyPairSyncResult<string, string> = Crypto.generateKeyPairSync("rsa", {
			modulusLength,
			publicKeyEncoding: {
				type: "spki",
				format: "pem"
			},
			privateKeyEncoding: {
				type: "pkcs8",
				format: "pem",
				cipher: "aes-256-cbc",
				passphrase
			}
		});

		return {
			publicKey: Buffer.from(keys.publicKey, "utf8"),
			privateKey: Buffer.from(keys.privateKey, "utf8")
		};

	}

	public static encrypt(data: Buffer, publicKey: Buffer): Buffer {

		return Crypto.publicEncrypt(publicKey, data);

	}

	public static decrypt(data: Buffer, privateKey: Buffer, passphrase: string = ""): Buffer {

		return Crypto.privateDecrypt({
			key: privateKey,
			passphrase
		}, data);

	}

	public static sign(data: Buffer, privateKey: Buffer, passphrase: string = ""): Buffer {

		return Crypto.privateEncrypt({
			key: privateKey,
			passphrase
		}, data);

	}

	public static verify(data: Buffer, publicKey: Buffer): Buffer {

		return Crypto.publicDecrypt(publicKey, data);

	}

}