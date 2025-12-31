/**
 * Galois Field (GF) Arithmetic for AES
 * 
 * This file implements Galois Field GF(2^8) operations used in the MixColumns transformation.
 * In GF(2^8), we work with polynomials with coefficients in {0,1} modulo the irreducible
 * polynomial m(x) = x^8 + x^4 + x^3 + x + 1 (0x11b in hex).
 */

// ====================================================================================
// GALOIS FIELD MULTIPLICATION
// ====================================================================================

/**
 * Multiply a byte by 2 in GF(2^8)
 * This is equivalent to left shift by 1, with conditional XOR if overflow occurs
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 2 in GF(2^8)
 */
export function multiplyByTwo(byte) {
    // Left shift by 1 (multiply by x in polynomial form)
    let result = byte << 1;

    // If the high bit was set (byte >= 128), we overflowed
    // XOR with 0x1b to reduce modulo the irreducible polynomial
    if (byte & 0x80) {
        result ^= 0x1b;
    }

    // Ensure result is a single byte
    return result & 0xff;
}

/**
 * Multiply a byte by 3 in GF(2^8)
 * Uses the fact that 3 = 2 + 1, so multiply by 3 = multiply by 2, then XOR with original
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 3 in GF(2^8)
 */
export function multiplyByThree(byte) {
    // byte * 3 = (byte * 2) XOR byte
    return multiplyByTwo(byte) ^ byte;
}

/**
 * Multiply two bytes in GF(2^8) using the peasant multiplication algorithm
 * This is a general multiplication function for any two bytes in the field
 * 
 * @param {number} a - First byte
 * @param {number} b - Second byte
 * @returns {number} Result of a * b in GF(2^8)
 */
export function galoisMultiply(a, b) {
    let product = 0;
    let tempA = a;
    let tempB = b;

    // Peasant multiplication algorithm
    for (let i = 0; i < 8; i++) {
        // If the lowest bit of b is set, XOR the current value of a into the product
        if (tempB & 1) {
            product ^= tempA;
        }

        // Check if high bit of a is set before shifting
        const highBitSet = tempA & 0x80;

        // Shift a left by 1 (multiply by x)
        tempA <<= 1;

        // If high bit was set, reduce modulo the irreducible polynomial
        if (highBitSet) {
            tempA ^= 0x1b;
        }

        // Shift b right by 1 (divide by x, or process next bit)
        tempB >>= 1;
    }

    return product & 0xff;
}

/**
 * Multiply a byte by 9 in GF(2^8)
 * Used in InvMixColumns transformation
 * 9 = 2^3 + 1, so we can compute it as (((byte * 2) * 2) * 2) XOR byte
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 9 in GF(2^8)
 */
export function multiplyByNine(byte) {
    // byte * 9 = byte * (2^3 + 1) = (byte * 8) XOR byte
    return multiplyByTwo(multiplyByTwo(multiplyByTwo(byte))) ^ byte;
}

/**
 * Multiply a byte by 11 (0x0b) in GF(2^8)
 * Used in InvMixColumns transformation
 * 11 = 2^3 + 2 + 1
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 11 in GF(2^8)
 */
export function multiplyByEleven(byte) {
    // byte * 11 = byte * (2^3 + 2 + 1) = (byte * 8) XOR (byte * 2) XOR byte
    const times2 = multiplyByTwo(byte);
    const times8 = multiplyByTwo(multiplyByTwo(times2));
    return times8 ^ times2 ^ byte;
}

/**
 * Multiply a byte by 13 (0x0d) in GF(2^8)
 * Used in InvMixColumns transformation
 * 13 = 2^3 + 2^2 + 1
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 13 in GF(2^8)
 */
export function multiplyByThirteen(byte) {
    // byte * 13 = byte * (2^3 + 2^2 + 1) = (byte * 8) XOR (byte * 4) XOR byte
    const times2 = multiplyByTwo(byte);
    const times4 = multiplyByTwo(times2);
    const times8 = multiplyByTwo(times4);
    return times8 ^ times4 ^ byte;
}

/**
 * Multiply a byte by 14 (0x0e) in GF(2^8)
 * Used in InvMixColumns transformation
 * 14 = 2^3 + 2^2 + 2
 * 
 * @param {number} byte - The byte to multiply
 * @returns {number} Result of byte * 14 in GF(2^8)
 */
export function multiplyByFourteen(byte) {
    // byte * 14 = byte * (2^3 + 2^2 + 2) = (byte * 8) XOR (byte * 4) XOR (byte * 2)
    const times2 = multiplyByTwo(byte);
    const times4 = multiplyByTwo(times2);
    const times8 = multiplyByTwo(times4);
    return times8 ^ times4 ^ times2;
}
