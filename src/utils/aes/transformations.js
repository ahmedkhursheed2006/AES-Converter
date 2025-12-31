/**
 * AES Transformations
 * 
 * This file implements the four main transformations used in AES encryption/decryption:
 * 1. SubBytes / InvSubBytes - Byte substitution using S-Box
 * 2. ShiftRows / InvShiftRows - Cyclically shift rows
 * 3. MixColumns / InvMixColumns - Mix data within columns using GF multiplication
 * 4. AddRoundKey - XOR state with round key
 */

import { S_BOX, INVERSE_S_BOX } from './constants.js';
import {
    multiplyByTwo,
    multiplyByThree,
    multiplyByNine,
    multiplyByEleven,
    multiplyByThirteen,
    multiplyByFourteen
} from './galoisField.js';
import { copyStateMatrix } from './utils.js';

// ====================================================================================
// SUBBYTES TRANSFORMATION
// ====================================================================================

/**
 * SubBytes Transformation
 * Substitutes each byte in the state matrix with a corresponding value from the S-Box
 * This provides non-linearity in the cipher
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function substituteBytes(state) {
    const newState = copyStateMatrix(state);

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            // Replace each byte with its S-Box value
            newState[row][col] = S_BOX[state[row][col]];
        }
    }

    return newState;
}

/**
 * Inverse SubBytes Transformation
 * Reverses the SubBytes transformation using the Inverse S-Box
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function inverseSubstituteBytes(state) {
    const newState = copyStateMatrix(state);

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            // Replace each byte with its Inverse S-Box value
            newState[row][col] = INVERSE_S_BOX[state[row][col]];
        }
    }

    return newState;
}

// ====================================================================================
// SHIFTROWS TRANSFORMATION
// ====================================================================================

/**
 * ShiftRows Transformation
 * Cyclically shifts the bytes in each row of the state matrix:
 * - Row 0: No shift
 * - Row 1: Shift left by 1
 * - Row 2: Shift left by 2
 * - Row 3: Shift left by 3
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function shiftRows(state) {
    const newState = copyStateMatrix(state);

    // Row 0: No shift
    newState[0] = [...state[0]];

    // Row 1: Shift left by 1
    newState[1] = [state[1][1], state[1][2], state[1][3], state[1][0]];

    // Row 2: Shift left by 2
    newState[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];

    // Row 3: Shift left by 3 (equivalent to shift right by 1)
    newState[3] = [state[3][3], state[3][0], state[3][1], state[3][2]];

    return newState;
}

/**
 * Inverse ShiftRows Transformation
 * Reverses the ShiftRows transformation by shifting rows to the right:
 * - Row 0: No shift
 * - Row 1: Shift right by 1
 * - Row 2: Shift right by 2
 * - Row 3: Shift right by 3
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function inverseShiftRows(state) {
    const newState = copyStateMatrix(state);

    // Row 0: No shift
    newState[0] = [...state[0]];

    // Row 1: Shift right by 1 (or left by 3)
    newState[1] = [state[1][3], state[1][0], state[1][1], state[1][2]];

    // Row 2: Shift right by 2
    newState[2] = [state[2][2], state[2][3], state[2][0], state[2][1]];

    // Row 3: Shift right by 3 (or left by 1)
    newState[3] = [state[3][1], state[3][2], state[3][3], state[3][0]];

    return newState;
}

// ====================================================================================
// MIXCOLUMNS TRANSFORMATION
// ====================================================================================

/**
 * MixColumns Transformation
 * Treats each column as a polynomial and multiplies it with a fixed polynomial
 * in GF(2^8). This provides diffusion in the cipher.
 * 
 * The multiplication matrix is:
 * [2 3 1 1]
 * [1 2 3 1]
 * [1 1 2 3]
 * [3 1 1 2]
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function mixColumns(state) {
    const newState = copyStateMatrix(state);

    // Process each column
    for (let col = 0; col < 4; col++) {
        const s0 = state[0][col];
        const s1 = state[1][col];
        const s2 = state[2][col];
        const s3 = state[3][col];

        // Apply the MixColumns matrix multiplication
        newState[0][col] = multiplyByTwo(s0) ^ multiplyByThree(s1) ^ s2 ^ s3;
        newState[1][col] = s0 ^ multiplyByTwo(s1) ^ multiplyByThree(s2) ^ s3;
        newState[2][col] = s0 ^ s1 ^ multiplyByTwo(s2) ^ multiplyByThree(s3);
        newState[3][col] = multiplyByThree(s0) ^ s1 ^ s2 ^ multiplyByTwo(s3);
    }

    return newState;
}

/**
 * Inverse MixColumns Transformation
 * Reverses the MixColumns transformation
 * 
 * The multiplication matrix is:
 * [14 11 13  9]
 * [ 9 14 11 13]
 * [13  9 14 11]
 * [11 13  9 14]
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[][]} Transformed state matrix
 */
export function inverseMixColumns(state) {
    const newState = copyStateMatrix(state);

    // Process each column
    for (let col = 0; col < 4; col++) {
        const s0 = state[0][col];
        const s1 = state[1][col];
        const s2 = state[2][col];
        const s3 = state[3][col];

        // Apply the Inverse MixColumns matrix multiplication
        newState[0][col] = multiplyByFourteen(s0) ^ multiplyByEleven(s1) ^
            multiplyByThirteen(s2) ^ multiplyByNine(s3);
        newState[1][col] = multiplyByNine(s0) ^ multiplyByFourteen(s1) ^
            multiplyByEleven(s2) ^ multiplyByThirteen(s3);
        newState[2][col] = multiplyByThirteen(s0) ^ multiplyByNine(s1) ^
            multiplyByFourteen(s2) ^ multiplyByEleven(s3);
        newState[3][col] = multiplyByEleven(s0) ^ multiplyByThirteen(s1) ^
            multiplyByNine(s2) ^ multiplyByFourteen(s3);
    }

    return newState;
}

// ====================================================================================
// ADDROUNDKEY TRANSFORMATION
// ====================================================================================

/**
 * AddRoundKey Transformation
 * XORs the state with a round key
 * This is the only step where the key is mixed into the state
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @param {number[][]} roundKey - 4x4 round key matrix
 * @returns {number[][]} Transformed state matrix
 */
export function addRoundKey(state, roundKey) {
    const newState = copyStateMatrix(state);

    for (let row = 0; row < 4; row++) {
        for (let col = 0; col < 4; col++) {
            // XOR each byte with the corresponding round key byte
            newState[row][col] = state[row][col] ^ roundKey[row][col];
        }
    }

    return newState;
}
