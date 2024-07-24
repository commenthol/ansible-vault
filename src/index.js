const { promisify } = require('util')
const crypto = require('crypto')
const { hexlify, unhexlify } = require('binascii')
const pkcs7 = require('./pkcs7')

const pbkdf2 = promisify(crypto.pbkdf2)

const HEADER = '$ANSIBLE_VAULT'
const AES256 = 'AES256'
const CIPHER = 'aes-256-ctr'
const DIGEST = 'sha256'

const PASSWORD = Symbol()

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

class Vault {
  /**
   * @param {object} param0
   * @param {string} param0.password vault password
   */
  constructor({ password }) {
    this[PASSWORD] = password
  }

  /**
   * @private
   * @param {string} header
   * @returns {boolean|string} for 1.2 "id" and for 1.1 `true` if header is ok, otherwise false
   */
  _checkHeader(header) {
    if (!header) {
      return false
    }
    const [_header, version, cipher, id = true] = header.split(';')

    if (_header === HEADER && /^1\.[12]$/.test(version) && cipher === AES256) {
      return id
    }
    return false
  }

  /**
   * @private
   * @param {Buffer} key
   * @param {Buffer} ciphertext
   * @returns {Buffer}
   */
  _hmac(key, ciphertext) {
    const hmac = crypto.createHmac(DIGEST, key)
    hmac.update(ciphertext)
    return hmac.digest()
  }

  /**
   * @private
   * @param {Buffer} salt
   * @returns {Promise<DerivedKey>}
   */
  async _derivedKey(salt) {
    if (!this[PASSWORD]) throw new Error('No password')

    const derivedKey = await pbkdf2(this[PASSWORD], salt, 10000, 80, DIGEST)
    return this._deriveKey(derivedKey)
  }

  /**
   * @private
   * @param {Buffer} salt
   * @returns {DerivedKey}
   */
  _derivedKeySync(salt) {
    if (!this[PASSWORD]) throw new Error('No password')

    const derivedKey = crypto.pbkdf2Sync(
      this[PASSWORD],
      salt,
      10000,
      80,
      DIGEST
    )
    return this._deriveKey(derivedKey)
  }

  /**
   * @private
   * @param {Buffer} derivedKey
   * @returns {DerivedKey}
   */
  _deriveKey(derivedKey) {
    const key = derivedKey.subarray(0, 32)
    const hmacKey = derivedKey.subarray(32, 64)
    const iv = derivedKey.subarray(64, 80)
    return {
      key,
      hmacKey,
      iv
    }
  }

  /**
   * Encrypt `secret` text
   * @param {string} secret
   * @param {string} id
   * @returns {Promise<string>} encrypted string
   */
  async encrypt(secret, id) {
    const salt = crypto.randomBytes(32)
    const derivedKey = await this._derivedKey(salt)
    return this._cipher(secret, id, salt, derivedKey)
  }

  /**
   * Synchronously encrypt `secret` text
   * @param {string} secret
   * @param {string} id
   * @returns {string} encrypted string
   */
  encryptSync(secret, id) {
    const salt = crypto.randomBytes(32)
    const derivedKey = this._derivedKeySync(salt)
    return this._cipher(secret, id, salt, derivedKey)
  }

  /**
   * @private
   * @param {string} secret
   * @param {string} id
   * @param {Buffer} salt
   * @param {DerivedKey} derivedKey
   * @returns
   */
  _cipher(secret, id, salt, derivedKey) {
    const { key, hmacKey, iv } = derivedKey
    const cipherF = crypto.createCipheriv(CIPHER, key, iv)
    const padded = Buffer.concat([
      Buffer.from(secret, 'utf-8'),
      pkcs7.pad(Buffer.from(secret, 'utf-8').length, 16)
    ])
    const ciphertext = Buffer.concat([
      cipherF.update(padded),
      cipherF.final()
    ])

    const hmac = this._hmac(hmacKey, ciphertext)
    const hex = [salt, hmac, ciphertext]
      .map((buf) => buf.toString('hex'))
      .join('\n')
    return this._pack(id, hex)
  }

  /**
   * @private
   * @param {Unpacked} unpacked
   * @param {DerivedKey} derivedKey
   * @returns
   */
  _decipher(unpacked, derivedKey) {
    const { hmac, ciphertext } = unpacked
    const { key, hmacKey, iv } = derivedKey
    const hmacComp = this._hmac(hmacKey, ciphertext)

    if (Buffer.compare(hmacComp, hmac) !== 0)
      throw new Error('Integrity check failed')

    const cipherF = crypto.createDecipheriv(CIPHER, key, iv)
    const buffer = pkcs7.unpad(
      Buffer.concat([cipherF.update(ciphertext), cipherF.final()]),
      16
    )

    return buffer.toString()
  }

  /**
   * @private
   * @param {string|undefined} id optional id
   * @param {string} hex hex encoded
   * @returns {string} ansible encoded secret
   */
  _pack(id, hex) {
    const header = id
      ? `${HEADER};1.2;${AES256};${id}\n`
      : `${HEADER};1.1;${AES256}\n`

    return (
      header +
      hexlify(hex)
        .match(/.{1,80}/g)
        .join('\n')
    )
  }

  /**
   * @private
   * @param {string} vault
   * @param {string|undefined} id optional id
   * @returns {Unpacked|undefined}
   */
  _unpack(vault, id) {
    const [header, ...hexValues] = vault.split(/\r?\n/)

    const _id = this._checkHeader(header)
    if (!_id) throw new Error('Bad vault header')
    if (id && id !== _id) return // only decrypt if `id` is matching id in header

    const [salt, hmac, ciphertext] = unhexlify(hexValues.join(''))
      .split(/\r?\n/)
      .map((hex) => Buffer.from(hex, 'hex'))

    if (!salt || !hmac || !ciphertext) throw new Error('Invalid vault')

    return { salt, hmac, ciphertext }
  }

  /**
   * Decrypt vault
   * @param {string} vault
   * @param {string|undefined} id optional id
   * @returns {Promise<string|undefined>}
   */
  async decrypt(vault, id) {
    const unpacked = this._unpack(vault, id)
    if (!unpacked) return
    const { salt } = unpacked

    const derivedKey = await this._derivedKey(salt)
    return this._decipher(unpacked, derivedKey)
  }

  /**
   * Synchronously decrypt vault
   * @param {string} vault
   * @param {string|undefined} id optional id
   * @returns {string|undefined}
   */
  decryptSync(vault, id) {
    const unpacked = this._unpack(vault, id)
    if (!unpacked) return
    const { salt } = unpacked

    const derivedKey = this._derivedKeySync(salt)
    return this._decipher(unpacked, derivedKey)
  }
}

module.exports = {
  Vault
}
