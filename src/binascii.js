/**
 * @license MIT
 * @copyright Copyright (c) 2014 Michał Budzyński (@michalbe)
 * @see https://github.com/michalbe/binascii
 * @see https://docs.python.org/2/library/binascii.html
 */

/**
 * @param {string} str
 * @returns {string}
 */
export function hexlify(str) {
  let result = ''
  for (let i = 0, l = str.length; i < l; i++) {
    const digit = str.charCodeAt(i).toString(16)
    const padded = ('00' + digit).slice(-2)
    result += padded
  }
  return result
}

/**
 * @param {string} str
 * @returns {string}
 */
export function unhexlify(str) {
  let result = ''
  for (var i = 0, l = str.length; i < l; i += 2) {
    result += String.fromCharCode(parseInt(str.slice(i, i + 2), 16))
  }
  return result
}
