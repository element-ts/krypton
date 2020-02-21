# krypton
A very light weight package written in Typescript combining `node/crypto` and `bcrypt` for some helpful methods.

> **NOTE**, I am not using my own crypto with this project, it is using recommend crypto from node and bcrypt.

## Import
Import what you need. You will most likely not need to import all of these.
```typescript
import {
    KrBcrypt,
    KrHash,
    KrHashAlgorithm,
    KrRSA,
    KrRSAKeyPair
} from "element-ts/krypton";
```

## Examples

### `KrBcrypt`
```typescript
const password: string = "1234";
const createdPassword: Buffer = await KrBcrypt.createPassword(password);
const checkPassword: boolean = await KrBcrypt.verifyPassword(password, createdPassword);
```

### `KrHash`
```typescript
const hashedData: Buffer = KrHash.hash(Buffer.from("Hello, world!");
const hashedData: Buffer = KrHash.hash(Buffer.from("Hello, world!", KrHashAlgorithm.sha512));

const hasher: KrHash = new KrHash()
hasher.append(Buffer.from("Hello"));
hasher.append(Buffer.from("World"));
const hashedData: Buffer = hasher.hash();
```

### `KrCipher`
```typescript
// instance
const cipher: KrCipher = new KrCipher(Buffer.from("password"));
const msg: Buffer = Buffer.from("Hello, world!");
const encryptedData: Buffer = cipher.encrypt(msg);
const decryptedData: Buffer = cipher.decrypt(encryptedData);
console.log(msg === decryptedData);

// static
const encryptedData: Buffer = KrCipher.encrypt(Buffer.from("Hello, world!"), Buffer.from("password"), Buffer.from("the-salt"));
const decryptedData: Buffer = KrCipher.decrypt(encryptedData, Buffer.from("password"), Buffer.from("the-salt"));

```

### `KrRSA`
```typescript

const keys: KrRSAKeyPair = KrRSA.generateKeys();

const message: string = "Hello, world!";
const dataUnEncrypted: Buffer = Buffer.from(message);
const dataEncrypted: Buffer = KrRSA.encrypt(dataUnEncrypted, keys.publicKey);
const dataDecrypted: Buffer = KrRSA.decrypt(dataEncrypted, keys.privateKey);

const messageDecrypted: string = dataDecrypted.toString("utf8");
```

## Documentation
You can view the
[declaration files](https://github.com/element-ts/krypton/***/master/dts) or even the
[source code](https://github.com/element-ts/krypton/tree/master/ts) on GitHub.

## Bugs
If you find any bugs please [create an issue on GitHub](https://github.com/element-ts/krypton/issues) or if you are old
fashioned email me at [elijah@elijahcobb.com](mailto:elijah@elijahcobb.com).