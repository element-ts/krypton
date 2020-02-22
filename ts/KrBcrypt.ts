import * as Bcrypt from "bcrypt";

export interface KrBcryptCreatePasswordReturn {
	salt: Buffer;
	password: Buffer;
}

export class KrBcrypt {

	public static async createPassword(password: string | Buffer): Promise<KrBcryptCreatePasswordReturn> {

		const value: string = typeof password === "string" ? password : password.toString("utf8");
		const salt: string = await Bcrypt.genSalt(10);
		const encryptedData: string = await Bcrypt.hash(value, salt);

		return {
			salt: Buffer.from(salt, "utf8"),
			password: Buffer.from(encryptedData, "utf8")
		};

	}

	public static async verifyPassword(plainText: string | Buffer, password: Buffer, salt: Buffer): Promise<boolean> {

		const rawPassword: string = typeof plainText === "string" ? plainText : plainText.toString("utf8");
		const hash: string = await Bcrypt.hash(rawPassword, salt.toString("utf8"));
		const hashData: Buffer = Buffer.from(hash, "utf8");

		return Buffer.compare(password, hashData) === 0;

	}

}