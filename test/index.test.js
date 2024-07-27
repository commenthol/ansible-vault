import { strictEqual } from 'assert'
import { Vault } from '../src/index.js'
import debug from 'debug'

const log = debug('test')

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

const vaultBadPkcs7Padding = `$ANSIBLE_VAULT;1.1;AES256
39616236653463303233376233653238346662373130323030353739386531666137626235653731
6664386130373163613138623161333861373531353863650a323233303933323963623834383730
39633230636265346538663164393832613737363533643863313034613931653762616264616230
3430316130363330300a353562613239346662343062623335396136633938643930306638323261
3239353563626639`

describe('ansible-vault', function () {
  const secret = 'password: superSecret123!'
  const password = 'pa$$w0rd'

  describe('general', function () {
    it('shall not expose password', function () {
      const v = new Vault({ password })
      const PASSWORD = Symbol()
      strictEqual(v[PASSWORD], undefined)
    })

    it('shall throw on wrong header', async function () {
      const v = new Vault({ password })
      const vault = ''
      try {
        await v.decrypt(vault)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Bad vault header')
      }
    })

    it('shall throw on wrong version', async function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.0;AES256\n6135643365643261'
      try {
        await v.decrypt(vault)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Bad vault header')
      }
    })

    it('shall throw on wrong cipher', async function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.0;AES128\n6135643365643261'
      try {
        await v.decrypt(vault)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Bad vault header')
      }
    })

    it('shall throw on missing content', async function () {
      const v = new Vault({ password })
      const vault = '$ANSIBLE_VAULT;1.1;AES256\n'
      try {
        await v.decrypt(vault)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Invalid vault')
      }
    })

    it('shall throw on compromised integrity', async function () {
      const v = new Vault({ password })
      try {
        await v.decrypt(vaultBadIntegrity)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Integrity check failed')
      }
    })

    it('shall throw on bad chars', async function () {
      const v = new Vault({ password })
      try {
        await v.decrypt(vaultBadValues)
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'Integrity check failed')
      }
    })

    it('shall throw on missing password', async function () {
      const v = new Vault({})
      try {
        await v.encrypt('vault')
        throw new Error()
      } catch (err) {
        strictEqual(err.message, 'No password')
      }
    })
  })

  describe('1.1', function () {
    it('shall decrypt', async function () {
      const v = new Vault({ password })
      const _secret = await v.decrypt(vault)
      strictEqual(_secret, secret)
    })

    it('shall encrypt and decrypt', async function () {
      const v = new Vault({ password })
      const _vault = await v.encrypt(secret)
      log(_vault)
      const _secret = await v.decrypt(_vault)
      strictEqual(_secret, secret)
    })

    it('shall encrypt and decrypt with special characters', async function () {
      const v = new Vault({ password })
      const secretWithSpecialChars = 'superduperpa§§'
      const _vault = await v.encrypt(secretWithSpecialChars)
      const _secret = await v.decrypt(_vault)
      strictEqual(_secret, secretWithSpecialChars)
    })

    it('should decrypt vault with bad padding', async function () {
      const v = new Vault({ password })
      const _secret = await v.decrypt(vaultBadPkcs7Padding)
      strictEqual(_secret, 'superduperpa§§§')
    })
  })

  describe('1.2', async function () {
    it('shall decrypt', async function () {
      const v = new Vault({ password })
      const _secret = await v.decrypt(vaultId, 'prod')
      strictEqual(_secret, secret)
    })

    it('shall decrypt with CLRF', async function () {
      const v = new Vault({ password })
      const _secret = await v.decrypt(vaultIdCLRF, 'prod')
      strictEqual(_secret, secret)
    })

    it("shall not decrypt if id doesn't match", async function () {
      const v = new Vault({ password })
      const _secret = await v.decrypt(vaultId, 'test')
      strictEqual(_secret, undefined)
    })

    it('shall encrypt and decrypt', async function () {
      const v = new Vault({ password })
      const _vault = await v.encrypt(secret, 'prod')
      log(_vault)
      strictEqual(_vault.substring(0, 30), '$ANSIBLE_VAULT;1.2;AES256;prod')
      const _secret = await v.decrypt(_vault)
      strictEqual(_secret, secret)
    })

    it('shall encrypt and decrypt (block size fits)', async function () {
      const v = new Vault({ password })
      const secret = 'abcdefgh'
      const _vault = await v.encrypt(secret, 'prod')
      log(_vault)
      strictEqual(_vault.substring(0, 30), '$ANSIBLE_VAULT;1.2;AES256;prod')
      const _secret = await v.decrypt(_vault)
      strictEqual(_secret, secret)
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
