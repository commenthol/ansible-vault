function pad (messageLength, blocksize) {
  if (blocksize > 256) throw new Error('can\'t pad blocks larger 256 bytes')
  const padLength = blocksize - (messageLength % blocksize)
  return Buffer.alloc(padLength, new Uint8Array([padLength]))
}

function unpad (padded, blocksize) {
  let len = padded.length
  const byte = padded[len - 1]
  if (byte > blocksize) return padded
  for (let i = len - byte; i < len; i++) {
    if (padded[i] !== byte) {
      return padded
    }
  }
  return padded.slice(0, len - byte)
}

module.exports = {
  pad,
  unpad
}
