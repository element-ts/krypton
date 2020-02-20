import * as Bcrypt from "bcrypt";

export class KrBcrypt {

	public static async createPassword(password: string | Buffer): Promise<Buffer> {

		const value: string = typeof password === "string" ? password : password.toString("utf8");
		const encryptedData: string = await Bcrypt.hash(value, 10);

		return Buffer.from(encryptedData, "utf8");

	}

	public static async verifyPassword(password: string | Buffer, data: Buffer): Promise<boolean> {

		const rawPassword: string = typeof password === "string" ? password : password.toString("utf8");
		const encryptedPassword: string = data.toString("utf8");

		return await Bcrypt.compare(rawPassword, encryptedPassword);

	}

}