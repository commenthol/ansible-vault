const { strictEqual } = require('assert')
const { Vault } = require('..')

const vault = `$ANSIBLE_VAULT;1.1;AES256
61356433656432613436613536366164366566633230656233333337343438383930623765613330
3864303630363231376632616264363335616536306237620a323433643266646263366330376138
65646365626433643265633534306336613861663332323337616539353565646339636139393333
6366333931663831360a393339323438303135616262656261653833653864343533373235613533
34366538643238633732393633363761616333366661313236366439626264373630`

const vaultId = `$ANSIBLE_VAULT;1.2;AES256;prod
63363765326134663661656366306361373736303032643563303938326431363233623665663337
3264383566303638313230316265656263323337373265300a613033373830666338373036616364
36626337383935306265353236663235633261663730666134373632623962633962326437393731
3630663066376161630a623132376461306361646437306436633361646331366462393361666235
31613431383436313564393661333633323864306464636138353932636430653963`

const vaultBadIntegrity = `$ANSIBLE_VAULT;1.2;AES256;prod
63363765326134663661656366306361373736303032643563303938326431363233623665663337
3264383566309938313230316265656263323337373265300a613033373830666338373036616364
36626337383935306265353236663235633261663730666134373632623962633962326437393731
3630663066376161630a623132376461306361646437306436633361646331366462393361666235
31613431383436313564393661333633323864306464636138353932636430653963`

const vaultBadValues = `$ANSIBLE_VAULT;1.2;AES256;prod
63363765326134663661656366306361373736303032643563303938326431363233623665663337
3264383566303638313230316265656263323337373265300a613033373830666338373036616364
36626337383935306265353236663235633261663730666134373632623962633962326437393731
3630663066376XX1630a623132376461306361646437306436633361646331366462393361666235
31613431383436313564393661333633323864306464636138353932636430653963`


const log = () => {} // console.log

describe('ansible-vault', function () {
  const secret = 'password: superSecret123!\n'
  const password = 'pa$$w0rd'

  describe('general', function () {
    it('shall not expose password', function () {
      const v = new Vault({ password })
      const PASSWORD = Symbol()
      strictEqual(v[PASSWORD], undefined)
    })

    it('shall throw on wrong header', function () {
      const v = new Vault({ password })
      const vault = ''
      return v.decrypt(vault)
        .catch(err => {
          strictEqual(err.message, 'Bad vault header')
        })
    })

    it('shall throw on wrong version', function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.0;AES256\n6135643365643261'
      return v.decrypt(vault)
        .catch(err => {
          strictEqual(err.message, 'Bad vault header')
        })
    })

    it('shall throw on wrong cipher', function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.0;AES128\n6135643365643261'
      return v.decrypt(vault)
        .catch(err => {
          strictEqual(err.message, 'Bad vault header')
        })
    })

    it('shall throw on missing content', function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.1;AES256\n'
      return v.decrypt(vault)
        .catch(err => {
          strictEqual(err.message, 'Invalid vault')
        })
    })

    it('shall throw on compromised integrity', function () {
      const v = new Vault({ password })
      return v.decrypt(vaultBadIntegrity)
        .catch(err => {
          strictEqual(err.message, 'Integrity check failed')
        })
    })

    it('shall throw on bad chars', function () {
      const v = new Vault({ password })
      return v.decrypt(vaultBadValues)
        .catch(err => {
          strictEqual(err.message, 'Integrity check failed')
        })
    })

    it('shall throw on missing password', function () {
      const v = new Vault({})
      return v.encrypt('vault')
        .catch(err => {
          strictEqual(err.message, 'No password')
        })
    })

  })

  describe('1.1', function () {
    it('shall decrypt', function () {
      const v = new Vault({ password })
      return v.decrypt(vault)
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })

    it('shall encrypt and decrypt', function () {
      const v = new Vault({ password })
      return v.encrypt(secret)
        .then(_vault => {
          log(_vault)
          return v.decrypt(_vault)
        })
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })
  })

  describe('1.2', function () {
    it('shall decrypt', function () {
      const v = new Vault({ password })
      return v.decrypt(vaultId, 'prod')
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })

    it('shall not decrypt if id doesn\'t match', function () {
      const v = new Vault({ password })
      return v.decrypt(vaultId, 'test')
        .then(_secret => {
          strictEqual(_secret, undefined)
        })
    })

    it('shall encrypt and decrypt', function () {
      const v = new Vault({ password })
      return v.encrypt(secret, 'prod')
        .then(_vault => {
          log(_vault)
          strictEqual(_vault.substring(0, 30), '$ANSIBLE_VAULT;1.2;AES256;prod')
          return v.decrypt(_vault)
        })
        .then(_secret => {
          strictEqual(_secret, secret)
        })
    })
  })
})
