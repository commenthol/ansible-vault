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

class Vault {
  constructor ({ password }) {
    this[PASSWORD] = password
  }

  _checkHeader (header) {
    if (!header) {
      return false
    }
    const [ _header, version, cipher, id = true ] = header.split(';')

    if (_header === HEADER && /^1\.[12]$/.test(version) && cipher === AES256) {
      return id
    }
    return false
  }

  _hmac (key, ciphertext) {
    const hmac = crypto.createHmac(DIGEST, key)
    hmac.update(ciphertext)
    return hmac.digest()
  }

  async _derivedKey (salt) {
    if (!this[PASSWORD]) throw new Error('No password')

    const derivedKey = await pbkdf2(this[PASSWORD], salt, 10000, 80, DIGEST)
    return this._deriveKey(derivedKey)
  }

  _derivedKeySync (salt) {
    if (!this[PASSWORD]) throw new Error('No password')

    const derivedKey = crypto.pbkdf2Sync(this[PASSWORD], salt, 10000, 80, DIGEST)
    return this._deriveKey(derivedKey)
  }

  _deriveKey (derivedKey) {
    const key = derivedKey.slice(0, 32)
    const hmacKey = derivedKey.slice(32, 64)
    const iv = derivedKey.slice(64, 80)
    return {
      key,
      hmacKey,
      iv
    }
  }

  async encrypt (secret, id) {
    const salt = crypto.randomBytes(32)
    const derivedKey = await this._derivedKey(salt)
    return this._cipher(secret, id, salt, derivedKey)
  }

  encryptSync (secret, id) {
    const salt = crypto.randomBytes(32)
    const derivedKey = this._derivedKeySync(salt)
    return this._cipher(secret, id, salt, derivedKey)
  }

  _cipher (secret, id, salt, derivedKey) {
    const { key, hmacKey, iv } = derivedKey
    const cipherF = crypto.createCipheriv(CIPHER, key, iv)
    const ciphertext = Buffer.concat([
      cipherF.update(secret),
      cipherF.update(pkcs7.pad(secret.length, 16)),
      cipherF.final()
    ])

    const hmac = this._hmac(hmacKey, ciphertext)
    const hex = [ salt, hmac, ciphertext ].map(buf => buf.toString('hex')).join('\n')

    return this._pack(id, hex)
  }

  _decypher (unpacked, derivedKey) {
    const { hmac, ciphertext } = unpacked
    const { key, hmacKey, iv } = derivedKey
    const hmacComp = this._hmac(hmacKey, ciphertext)

    if (Buffer.compare(hmacComp, hmac) !== 0) throw new Error('Integrity check failed')

    const cipherF = crypto.createDecipheriv(CIPHER, key, iv)
    const buffer = pkcs7.unpad(Buffer.concat([
      cipherF.update(ciphertext),
      cipherF.final()
    ]), 16)

    return buffer.toString()
  }

  _pack (id, hex) {
    const header = id
      ? `${HEADER};1.2;${AES256};${id}\n`
      : `${HEADER};1.1;${AES256}\n`

    return header + hexlify(hex).match(/.{1,80}/g).join('\n')
  }

  _unpack (vault, id) {
    const [ header, ...hexValues ] = vault.split('\n')

    const _id = this._checkHeader(header)
    if (!_id) throw new Error('Bad vault header')
    if (id && id !== _id) return // only decrypt if `id` is matching id in header

    const [ salt, hmac, ciphertext ] = unhexlify(hexValues.join(''))
      .split('\n')
      .map(hex => Buffer.from(hex, 'hex'))

    if (!salt || !hmac || !ciphertext) throw new Error('Invalid vault')

    return { salt, hmac, ciphertext }
  }

  async decrypt (vault, id) {
    const unpacked = this._unpack(vault, id)
    if (!unpacked) return
    const { salt } = unpacked

    const derivedKey = await this._derivedKey(salt)
    return this._decypher(unpacked, derivedKey)
  }

  decryptSync (vault, id) {
    const unpacked = this._unpack(vault, id)
    if (!unpacked) return
    const { salt } = unpacked

    const derivedKey = this._derivedKeySync(salt)
    return this._decypher(unpacked, derivedKey)
  }
}

module.exports = {
  Vault
}
