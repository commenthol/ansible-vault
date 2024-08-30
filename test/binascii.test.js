import assert from 'node:assert'
import { hexlify, unhexlify } from '../src/binascii.js'

describe('binascii', function () {
  it('shall return a string', function () {
    assert.equal(hexlify(''), '')
  })

  it('shall hexlify char', function () {
    assert.equal(hexlify('A'), '41')
  })

  it('shall hexlify string', function () {
    assert.equal(hexlify('Pamietamy 44'), '50616d696574616d79203434')
  })

  it('shall hexlify binary data', function () {
    assert.equal(hexlify("7z¼¯'\u001c"), '377abcaf271c')
  })

  it('shall ensure that single-digit codes are correctly padded', function () {
    assert.equal(hexlify('\n'), '0a')
  })

  it('shall unhexlify char', function () {
    assert.equal(unhexlify(hexlify('A')), 'A')
  })

  it('shall unhexlify string', function () {
    assert.equal(unhexlify('50616d696574616d79203434'), 'Pamietamy 44')
  })

  it('shall unhexlify binary data', function () {
    assert.equal(unhexlify('377abcaf271c'), "7z¼¯'\u001c")
  })
})
