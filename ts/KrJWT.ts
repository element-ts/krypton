/**
 * Elijah Cobb
 * elijah@elijahcobb.com
 * elijahcobb.com
 * github.com/elijahjcobb
 */

import * as Crypto from "crypto";

export class KrJWT<T extends object> {

	private readonly _payload: T;

	private constructor(payload: T) {

		this._payload = payload;

	}

	private base64(value: string): string {
		return Buffer.from(value, "utf8").toString("base64");
	}

	private getHeader(): string {
		return KrJWT.encode(this.base64(JSON.stringify({
			"alg": "HS256",
			"typ": "JWT"
		})));
	}

	private getPayload(): string {
		return KrJWT.encode(this.base64(JSON.stringify(this._payload)));
	}

	private static encode(value: string): string {
		return value
			.replace(RegExp("=", "g"), "")
			.replace(RegExp("\\+", "g"), "-")
			.replace(RegExp("/", "g"), "_");
	}

	private static decodePayload<T>(value: string): T {
		const base64 = value
			.replace(RegExp("-", "g"), "+")
			.replace(RegExp("_", "g"), "/");

		return JSON.parse(Buffer.from(base64, "base64").toString("utf8"));

	}

	private static getSignature(header: string, payload: string, secret: Buffer): string {
		return this.encode(Crypto.createHmac("sha256", secret, {}).update(Buffer.from(`${header}.${payload}`)).digest().toString("base64"));
	}

	public static sign<T extends object>(value: T, secret: Buffer): string {

		const jwt = new KrJWT<T>(value);
		const header = jwt.getHeader();
		const payload = jwt.getPayload();
		const sig = KrJWT.getSignature(header, payload, secret);
		return `${header}.${payload}.${sig}`;

	}

	public static verify<T extends object>(token: string, secret: Buffer): T | undefined {

		const sections = token.split(".");
		if (sections.length !== 3) return undefined;

		const header = sections[0];
		const payload = sections[1];
		const providedSignature = sections[2];
		const realSignature = KrJWT.getSignature(header, payload, secret);
		if (providedSignature !== realSignature) return undefined;

		return KrJWT.decodePayload(payload);

	}

}