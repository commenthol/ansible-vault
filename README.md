# ansible-vault

> An Ansible vault compatible en- and decryption library for javascript

## usage

encrypt

```js
const { Vault } = require('ansible-vault')

const v = new Vault({ password: 'pa$$w0rd' })
v.encrypt('superSecret123').then(console.log)

//> $ANSIBLE_VAULT;1.1;AES256
//> 36323735613631383731326630353438323237326239626564653637393230643764653937373937
//> 6263313335633536653533343136663437363666333630310a656434373634633063396562323437
//> 66653763363135326233376361623533613536333836313362666338396562316164653765353163
//> 3139383238353439340a386264313934343236316561633237653231343432353363303736323831
//> 6638
```

decrypt

```js
const { Vault } = require('ansible-vault')

const vault = `$ANSIBLE_VAULT;1.1;AES256
36323735613631383731326630353438323237326239626564653637393230643764653937373937
6263313335633536653533343136663437363666333630310a656434373634633063396562323437
66653763363135326233376361623533613536333836313362666338396562316164653765353163
3139383238353439340a386264313934343236316561633237653231343432353363303736323831
6638`

const v = new Vault({ password: 'pa$$w0rd' })
v.decrypt(vault).then(console.log)
//> superSecret123
```

## license

MIT Licensed

## references

<!-- !ref -->

* [vault-source][vault-source]

<!-- ref! -->

[vault-source]: https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py

[Ansible®](https://docs.ansible.com/ansible/latest/dev_guide/style_guide/trademarks.html) is a registered trademark of [RedHat®](https://www.redhat.com/en) (I hope this is correct...)
