import {KrBcrypt, KrHash, KrHashAlgorithm, KrRSA, KrRSAKeyPair, KrCipher} from "../index";
import {KrBcryptCreatePasswordReturn} from "../KrBcrypt";
import has = Reflect.has;

describe("KrCipher", (): void => {

	test("Instance", (): void => {

		const cipher: KrCipher = new KrCipher(Buffer.from("alpine"));
		expect(cipher).toBeDefined();

		const msg: string = "Hello, world!";
		const msgData: Buffer = Buffer.from(msg);
		const encryptedData: Buffer = cipher.encrypt(msgData);
		expect(encryptedData).not.toEqual(msgData);
		const decryptedData: Buffer = cipher.decrypt(encryptedData);
		expect(decryptedData).toEqual(msgData);


	});

	test("Static", (): void => {

		const msg: string = "Hello, world!";
		const password: string = "alpine";
		const msgData: Buffer = Buffer.from(msg);
		const passwordData: Buffer = Buffer.from(password);
		const saltData: Buffer = Buffer.from("32ruh2ifuhwefiuh2fiuwehfliukwefhlwiufhwlekfuhjwelkfjhwe");

		const encryptedData: Buffer = KrCipher.encrypt(msgData, passwordData, saltData);
		expect(encryptedData).not.toEqual(msgData);
		const decryptedData: Buffer = KrCipher.decrypt(encryptedData, passwordData, saltData);
		expect(decryptedData).toEqual(msgData);

	});

	test("Static Without Salt", (): void => {

		const msg: string = "Hello, world!";
		const password: string = "alpine";
		const msgData: Buffer = Buffer.from(msg);
		const passwordData: Buffer = Buffer.from(password);

		const encryptedData: Buffer = KrCipher.encrypt(msgData, passwordData);
		expect(encryptedData).not.toEqual(msgData);
		const decryptedData: Buffer = KrCipher.decrypt(encryptedData, passwordData);
		expect(decryptedData).toEqual(msgData);

	});

});

describe("KrBcrypt", (): void => {

	test("Create Password via String", async (): Promise<void> => {

		const res: KrBcryptCreatePasswordReturn = await KrBcrypt.createPassword("password");

		expect(res.password).toBeDefined();
		expect(res.salt).toBeDefined();

	});

	test("Create Password via Buffer", async (): Promise<void> => {

		const data: Buffer = Buffer.from("password");
		const hash: KrBcryptCreatePasswordReturn = await KrBcrypt.createPassword(data);

		expect(hash.password).toBeDefined();
		expect(hash.salt).toBeDefined();

	});

	test("Verify Password via String", async (): Promise<void> => {

		const password: string = "password";
		const hash: KrBcryptCreatePasswordReturn = await KrBcrypt.createPassword(password);
		const checkPassword: boolean = await KrBcrypt.verifyPassword(password, hash.password, hash.salt);
		const failPassword: boolean = await KrBcrypt.verifyPassword(password + "FAIL!", hash.password, hash.salt);

		expect(hash.salt).toBeDefined();
		expect(hash.password).toBeDefined();
		expect(checkPassword).toEqual(true);
		expect(failPassword).toEqual(false);

	});

	test("Verify Password via Buffer", async (): Promise<void> => {

		const password: string = "password";
		const passwordData: Buffer = Buffer.from(password);
		const hash: KrBcryptCreatePasswordReturn = await KrBcrypt.createPassword(passwordData);
		const checkPassword: boolean = await KrBcrypt.verifyPassword(passwordData, hash.password, hash.salt);
		const failPassword: boolean = await KrBcrypt.verifyPassword(Buffer.from(password + "FAIL!"), hash.password, hash.salt);

		expect(hash.salt).toBeDefined();
		expect(hash.password).toBeDefined();
		expect(checkPassword).toEqual(true);
		expect(failPassword).toEqual(false);

	});

});

describe("KrHash", (): void => {

	test("Static", (): void => {

		const data: Buffer = Buffer.from("Hello, world!");
		const hashed: Buffer = KrHash.hash(data);
		const hashed2: Buffer = KrHash.hash(data);

		expect(data).not.toEqual(hashed);
		expect(hashed2).toEqual(hashed);
		expect(hashed).toBeDefined();

	});

	test("Instance", (): void => {

		const hash: KrHash = new KrHash();

		hash.append(Buffer.from("Hello"));
		hash.append(Buffer.from("my"));
		hash.append(Buffer.from("name"));
		hash.append(Buffer.from("is"));
		hash.append(Buffer.from("Bob"));

		const hashed: Buffer = hash.hash();

		expect(hashed).toBeDefined();

	});

	test("Different Algorithm", (): void => {

		const hash: KrHash = new KrHash(KrHashAlgorithm.md5);

		hash.append(Buffer.from("Hello"));

		const hashed: Buffer = hash.hash();

		expect(hashed).toBeDefined();

	});

});

describe("KrRSA", (): void => {

	test("Generate Keys", (): void => {

		const keys: KrRSAKeyPair = KrRSA.generateKeys();

		expect(keys.publicKey).toBeDefined();
		expect(keys.privateKey).toBeDefined();

	});

	test("Encryption", (): void => {

		const keys: KrRSAKeyPair = KrRSA.generateKeys();
		const message: string = "Hello, world!";
		const dataUnEncrypted: Buffer = Buffer.from(message);
		const dataEncrypted: Buffer = KrRSA.encrypt(dataUnEncrypted, keys.publicKey);

		expect(dataEncrypted).toBeDefined();

	});

	test("Decryption", (): void => {

		const keys: KrRSAKeyPair = KrRSA.generateKeys();
		const message: string = "Hello, world!";
		const dataUnEncrypted: Buffer = Buffer.from(message);
		const dataEncrypted: Buffer = KrRSA.encrypt(dataUnEncrypted, keys.publicKey);
		const dataDecrypted: Buffer = KrRSA.decrypt(dataEncrypted, keys.privateKey);
		const messageDecrypted: string = dataDecrypted.toString("utf8");
		const messageEncrypted: string = dataEncrypted.toString("utf8");

		expect(dataEncrypted).toBeDefined();
		expect(messageDecrypted).toBeDefined();
		expect(messageDecrypted).toEqual(message);
		expect(messageEncrypted).not.toEqual(message);

	});

	test("Decryption with Low Modulus", (): void => {

		const keys: KrRSAKeyPair = KrRSA.generateKeys(512);
		const message: string = "Hello!";
		const dataUnEncrypted: Buffer = Buffer.from(message);
		const dataEncrypted: Buffer = KrRSA.encrypt(dataUnEncrypted, keys.publicKey);
		const dataDecrypted: Buffer = KrRSA.decrypt(dataEncrypted, keys.privateKey);
		const messageDecrypted: string = dataDecrypted.toString("utf8");
		const messageEncrypted: string = dataEncrypted.toString("utf8");

		expect(dataEncrypted).toBeDefined();
		expect(messageDecrypted).toBeDefined();
		expect(messageDecrypted).toEqual(message);
		expect(messageEncrypted).not.toEqual(message);

	});

	test("Decryption with Passphrase", (): void => {

		const passphrase: string = "taco";

		const keys: KrRSAKeyPair = KrRSA.generateKeys(undefined, passphrase);
		const message: string = "Hello, world!";
		const dataUnEncrypted: Buffer = Buffer.from(message);
		const dataEncrypted: Buffer = KrRSA.encrypt(dataUnEncrypted, keys.publicKey);

		let err: any | undefined;

		try {
			KrRSA.decrypt(dataEncrypted, keys.privateKey);
		} catch (e) {
			err = e;
		}

		expect(err).toBeTruthy();

		const dataDecrypted: Buffer = KrRSA.decrypt(dataEncrypted, keys.privateKey, passphrase);
		const messageDecrypted: string = dataDecrypted.toString("utf8");
		const messageEncrypted: string = dataEncrypted.toString("utf8");

		expect(dataEncrypted).toBeDefined();
		expect(messageDecrypted).toBeDefined();
		expect(messageDecrypted).toEqual(message);
		expect(messageEncrypted).not.toEqual(message);

	});

	test("Sign and Verify", (): void => {

		const passphrase: string = "password";
		const keys: KrRSAKeyPair = KrRSA.generateKeys(undefined, passphrase);
		const message: string = "Hello, world!";
		const dataToBeSigned: Buffer = Buffer.from(message);
		const signedData: Buffer = KrRSA.sign(dataToBeSigned, keys.privateKey, passphrase);
		expect(signedData).toBeDefined();
		expect(signedData).not.toEqual(dataToBeSigned);
		const verifiedData: Buffer = KrRSA.verify(signedData, keys.publicKey);
		expect(verifiedData).toBeDefined();
		expect(verifiedData).not.toEqual(signedData);
		expect(verifiedData).toEqual(dataToBeSigned);
		const verifiedMessage: string = verifiedData.toString("utf8");
		expect(verifiedMessage).toEqual(message);

	});


});