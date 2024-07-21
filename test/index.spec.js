const { strictEqual } = require('assert')
const { Vault } = require('..')
const log = require('debug')('test')

const vault = `$ANSIBLE_VAULT;1.1;AES256
37333730633265356131656330306537623666613631386461653831666535626462396366663434
6636366139393135623266336635323566623437613738320a653335663533636163656431623965
31633361343932363361333862303033316161666461313261623639303238616462653161316336
3933366163366665650a396236616335626132653038393330633035383864646564386535393831
38376361376666653862366337356365616236346137346436653566386663366562`

const vaultId = `$ANSIBLE_VAULT;1.2;AES256;prod
38373439396163396339326133633263383839646331346366396562666335653162346332646265
6164363632396564306131373030306630613834353664630a656538316632613366366632653463
66366535636562393063383665376563383838316364313661636462343333663961353438343831
3863303135376437660a346135623536376631666130376336306263376666396336323261306135
39373133326337656366313132363763363465343364613461393763343731313363`

const vaultBadIntegrity = `$ANSIBLE_VAULT;1.2;AES256;prod
37336134643233303839636435313435343930623234346237623734303234393934636636646333
3061356466639965393832656564346330346565656162380a653935303936666166333863333832
63336239663162643136626133613962373230376562323362643336393862626661383461306366
6463623430326566650a376235366430353633353338313935363564366433613863343230333864
30353030346364363065373137356239386231303862373939313735303131373139`

const vaultBadValues = `$ANSIBLE_VAULT;1.2;AES256;prod
37336134643233303839636435313435343930623234346237623734303234393934636636646333
3061356466633365393832656564346330346565656162380a653935303936666166333863333832
63336239663162643136626133613962373230376562323362643336393862626661383461306366
6463623430326XX6650a376235366430353633353338313935363564366433613863343230333864
30353030346364363065373137356239386231303862373939313735303131373139`

const vaultIdCLRF = `$ANSIBLE_VAULT;1.2;AES256;prod\r
38373439396163396339326133633263383839646331346366396562666335653162346332646265\r
6164363632396564306131373030306630613834353664630a656538316632613366366632653463\r
66366535636562393063383665376563383838316364313661636462343333663961353438343831\r
3863303135376437660a346135623536376631666130376336306263376666396336323261306135\r
39373133326337656366313132363763363465343364613461393763343731313363`

describe('ansible-vault', function () {
  const secret = 'password: superSecret123!'
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

    it('shall encrypt and decrypt with special characters', function () {
      const v = new Vault({ password })
      const secretWithSpecialChars = "pa§§w0rd"
      return v.encrypt(secretWithSpecialChars, 'prod')
          .then(_vault => {
            log(_vault)
            return v.decrypt(_vault)
          })
          .then(_secret => {
            strictEqual(_secret, secretWithSpecialChars)
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
    it('shall decrypt with CLRF', function () {
      const v = new Vault({ password })
      return v.decrypt(vaultIdCLRF, 'prod')
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

    it('shall encrypt and decrypt (block size fits)', function () {
      const v = new Vault({ password })
      const secret = 'abcdefgh'
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



  describe('sync operations', function () {
    it('shall decrypt synchronously', function () {
      const v = new Vault({ password })
      strictEqual(v.decryptSync(vault), secret)
    })

    it('shall encrypt and decrypt synchronously', function () {
      const v = new Vault({ password })
      strictEqual(v.decryptSync(v.encryptSync(secret)), secret)
    })
  })

})
