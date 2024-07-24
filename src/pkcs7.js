/**
 * pkcs7 pad 
 * @param {number} messageLength 
 * @param {number} blocksize 
 * @returns {Buffer}
 */
function pad (messageLength, blocksize) {
  if (blocksize > 256) throw new Error('can\'t pad blocks larger 256 bytes')
  const padLength = blocksize - (messageLength % blocksize)
  return Buffer.alloc(padLength, Buffer.from([padLength]))
}

/**
 * pkcs7 unpad 
 * @param {Buffer} padded 
 * @param {number} blocksize 
 * @returns {Buffer}
 */
 function unpad (padded, blocksize) {
  let len = padded.length
  const byte = padded[len - 1]
  if (byte > blocksize) return padded
  for (let i = len - byte; i < len; i++) {
    if (padded[i] !== byte) {
      return padded
    }
  }
  return padded.subarray(0, len - byte)
}

module.exports = {
  pad,
  unpad
}
