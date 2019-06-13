const { promisify } = require('util')
const crypto = require('crypto')
const { hexlify, unhexlify } = require('binascii')

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
    const aesKey = derivedKey.slice(0, 32)
    const hmacKey = derivedKey.slice(32, 64)
    const aesNonce = derivedKey.slice(64, 80)
    return {
      aesKey,
      hmacKey,
      aesNonce
    }
  }

  async encrypt (secret, id) {
    const salt = crypto.randomBytes(32)
    const { aesKey, hmacKey, aesNonce } = await this._derivedKey(salt)

    secret = secret + Array(16 - (secret.length % 16)).fill('\r').join('') // PKCS7 padding

    const cipherF = crypto.createCipheriv(CIPHER, aesKey, aesNonce)
    const ciphertext = Buffer.concat([
      cipherF.update(secret),
      cipherF.final()
    ])

    const hmac = this._hmac(hmacKey, ciphertext)
    const hex = [ salt, hmac, ciphertext ].map(buf => buf.toString('hex')).join('\n')

    const header = id
      ? `${HEADER};1.2;${AES256};${id}\n`
      : `${HEADER};1.1;${AES256}\n`

    return header + hexlify(hex).match(/.{1,80}/g).join('\n')
  }

  async decrypt (vault, id) {
    const [ header, ...hexValues ] = vault.split('\n')

    const _id = this._checkHeader(header)
    if (!_id) throw new Error('Bad vault header')
    if (id && id !== _id) return // only decrypt if `id` is matching id in header

    const [ salt, hmac, ciphertext ] = unhexlify(hexValues.join(''))
      .split('\n')
      .map(hex => Buffer.from(hex, 'hex'))

    if (!salt || !hmac || !ciphertext) throw new Error('Invalid vault')

    const { aesKey, hmacKey, aesNonce } = await this._derivedKey(salt)
    const hmacComp = this._hmac(hmacKey, ciphertext)

    if (Buffer.compare(hmacComp, hmac) !== 0) throw new Error('Integrity check failed')

    const cipherF = crypto.createDecipheriv(CIPHER, aesKey, aesNonce)
    const buffer = Buffer.concat([
      cipherF.update(ciphertext),
      cipherF.final()
    ])

    return buffer.toString()
      .replace(/\r{1,16}$/, '') // remove PKCS7 padding
  }
}

module.exports = {
  Vault
}
