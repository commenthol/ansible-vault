export type DerivedKey = {
    key: Buffer;
    hmacKey: Buffer;
    iv: Buffer;
};
export type Unpacked = {
    salt: Buffer;
    hmac: Buffer;
    ciphertext: Buffer;
};
/**
 * @typedef DerivedKey
 * @property {Buffer} key
 * @property {Buffer} hmacKey
 * @property {Buffer} iv
 */
/**
 * @typedef Unpacked
 * @property {Buffer} salt
 * @property {Buffer} hmac
 * @property {Buffer} ciphertext
 */
export class Vault {
    /**
     * @param {object} param0
     * @param {string} param0.password vault password
     */
    constructor({ password }: {
        password: string;
    });
    /**
     * @private
     * @param {string} header
     * @returns {boolean|string} for 1.2 "id" and for 1.1 `true` if header is ok, otherwise false
     */
    private _checkHeader;
    /**
     * @private
     * @param {Buffer} key
     * @param {Buffer} ciphertext
     * @returns {Buffer}
     */
    private _hmac;
    /**
     * @private
     * @param {Buffer} salt
     * @returns {Promise<DerivedKey>}
     */
    private _derivedKey;
    /**
     * @private
     * @param {Buffer} salt
     * @returns {DerivedKey}
     */
    private _derivedKeySync;
    /**
     * @private
     * @param {Buffer} derivedKey
     * @returns {DerivedKey}
     */
    private _deriveKey;
    /**
     * Encrypt `secret` text
     * @param {string} secret
     * @param {string} id
     * @returns {Promise<string>} encrypted string
     */
    encrypt(secret: string, id: string): Promise<string>;
    /**
     * Synchronously encrypt `secret` text
     * @param {string} secret
     * @param {string} id
     * @returns {string} encrypted string
     */
    encryptSync(secret: string, id: string): string;
    /**
     * @private
     * @param {string} secret
     * @param {string} id
     * @param {Buffer} salt
     * @param {DerivedKey} derivedKey
     * @returns
     */
    private _cipher;
    /**
     * @private
     * @param {Unpacked} unpacked
     * @param {DerivedKey} derivedKey
     * @returns
     */
    private _decipher;
    /**
     * @private
     * @param {string|undefined} id optional id
     * @param {string} hex hex encoded
     * @returns {string} ansible encoded secret
     */
    private _pack;
    /**
     * @private
     * @param {string} vault
     * @param {string|undefined} id optional id
     * @returns {Unpacked|undefined}
     */
    private _unpack;
    /**
     * Decrypt vault
     * @param {string} vault
     * @param {string|undefined} id optional id
     * @returns {Promise<string|undefined>}
     */
    decrypt(vault: string, id: string | undefined): Promise<string | undefined>;
    /**
     * Synchronously decrypt vault
     * @param {string} vault
     * @param {string|undefined} id optional id
     * @returns {string|undefined}
     */
    decryptSync(vault: string, id: string | undefined): string | undefined;
    [PASSWORD]: string;
}
declare const PASSWORD: unique symbol;
export {};
