# ansible-vault

[![NPM version](https://badge.fury.io/js/ansible-vault.svg)](https://www.npmjs.com/package/ansible-vault/)
[![Build Status](https://api.travis-ci.com/commenthol/ansible-vault.svg?branch=master)](https://travis-ci.com/commenthol/ansible-vault)

> An Ansible vault compatible en- and decryption library for javascript

## usage

encrypt

```js
const { Vault } = require('ansible-vault')

const v = new Vault({ password: 'pa$$w0rd' })
v.encrypt('superSecret123').then(console.log)

//> $ANSIBLE_VAULT;1.1;AES256
//> 33383239333036363833303565653032383832663162356533343630623030613133623032636566
//> 6536303436646561356461623866386133623462383832620a646363626137626635353462386430
//> 34333937313366383038346135656563316236313139333933383139376333353266666436316536
//> 6335376265313432610a313537363637383264646261303637646631346137393964386432313633
//> 3666
```

decrypt

```js
const { Vault } = require('ansible-vault')

const vault = `$ANSIBLE_VAULT;1.1;AES256
33383239333036363833303565653032383832663162356533343630623030613133623032636566
6536303436646561356461623866386133623462383832620a646363626137626635353462386430
34333937313366383038346135656563316236313139333933383139376333353266666436316536
6335376265313432610a313537363637383264646261303637646631346137393964386432313633
3666`

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
