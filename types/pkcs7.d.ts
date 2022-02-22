/**
 * pkcs7 pad
 * @param {number} messageLength
 * @param {number} blocksize
 * @returns {Buffer}
 */
export function pad(messageLength: number, blocksize: number): Buffer;
/**
 * pkcs7 unpad
 * @param {Buffer} padded
 * @param {number} blocksize
 * @returns {Buffer}
 */
export function unpad(padded: Buffer, blocksize: number): Buffer;
