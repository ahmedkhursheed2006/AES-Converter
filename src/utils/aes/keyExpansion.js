/**
 * AES Key Expansion Algorithm
 * 
 * This file implements the key expansion algorithm for AES-256.
 * It takes a 256-bit (32 byte) key and expands it into 15 round keys
 * (one for the initial round and 14 for each of the 14 rounds).
 */

import { S_BOX, ROUND_CONSTANTS, KEY_SIZE_WORDS, NUMBER_OF_ROUNDS } from './constants.js';

// ====================================================================================
// KEY EXPANSION HELPER FUNCTIONS
// ====================================================================================

/**
 * Rotate a 4-byte word left by one byte
 * Example: [a, b, c, d] becomes [b, c, d, a]
 * 
 * @param {number[]} word - 4-byte array
 * @returns {number[]} Rotated word
 */
function rotateWord(word) {
    return [word[1], word[2], word[3], word[0]];
}

/**
 * Apply S-Box substitution to each byte in a word
 * 
 * @param {number[]} word - 4-byte array
 * @returns {number[]} Substituted word
 */
function substituteWord(word) {
    return word.map(byte => S_BOX[byte]);
}

/**
 * XOR two words (4-byte arrays)
 * 
 * @param {number[]} word1 - First 4-byte array
 * @param {number[]} word2 - Second 4-byte array
 * @returns {number[]} XORed result
 */
function xorWords(word1, word2) {
    return word1.map((byte, index) => byte ^ word2[index]);
}

// ====================================================================================
// MAIN KEY EXPANSION FUNCTION
// ====================================================================================

/**
 * Expand a 256-bit key into round keys for all rounds
 * 
 * AES-256 uses:
 * - 8 words (32 bytes) for the initial key
 * - 4 words per round key
 * - 15 round keys total (initial + 14 rounds)
 * - Total: 60 words (240 bytes)
 * 
 * @param {number[]} key - 32-byte key array
 * @returns {Object} Object containing:
 *   - roundKeys: Array of 15 round key matrices (4x4)
 *   - expansionDetails: Details of each step for visualization
 */
export function expandKey(key) {
    // Total number of words needed: 4 words per round key * 15 round keys
    const totalWords = 4 * (NUMBER_OF_ROUNDS + 1); // 60 words

    // Array to hold all words
    const words = [];

    // Array to hold expansion details for visualization
    const expansionDetails = [];

    // First 8 words come directly from the key
    for (let i = 0; i < KEY_SIZE_WORDS; i++) {
        words[i] = [
            key[4 * i],
            key[4 * i + 1],
            key[4 * i + 2],
            key[4 * i + 3]
        ];
    }

    // Generate remaining words
    for (let i = KEY_SIZE_WORDS; i < totalWords; i++) {
        let temp = [...words[i - 1]];
        const stepDetails = { wordIndex: i };

        // Every 8th word (for AES-256)
        if (i % KEY_SIZE_WORDS === 0) {
            // Apply RotWord, SubWord, and XOR with Rcon
            const beforeRotate = [...temp];
            temp = rotateWord(temp);
            const afterRotate = [...temp];

            temp = substituteWord(temp);
            const afterSubstitute = [...temp];

            const rconValue = ROUND_CONSTANTS[i / KEY_SIZE_WORDS];
            temp[0] ^= rconValue;

            stepDetails.operation = 'RotWord → SubWord → Rcon';
            stepDetails.beforeRotate = beforeRotate;
            stepDetails.afterRotate = afterRotate;
            stepDetails.afterSubstitute = afterSubstitute;
            stepDetails.rconValue = rconValue;
        }
        // Every 4th word after the 4th word (but not every 8th)
        else if (i % KEY_SIZE_WORDS === 4) {
            // Apply SubWord only (specific to AES-256)
            stepDetails.operation = 'SubWord only';
            stepDetails.before = [...temp];
            temp = substituteWord(temp);
        }
        else {
            stepDetails.operation = 'XOR only';
        }

        // XOR with word from 8 positions back
        words[i] = xorWords(temp, words[i - KEY_SIZE_WORDS]);
        stepDetails.result = [...words[i]];

        expansionDetails.push(stepDetails);
    }

    // Convert words into round key matrices (4x4)
    const roundKeys = [];

    for (let round = 0; round <= NUMBER_OF_ROUNDS; round++) {
        const roundKey = Array(4).fill(null).map(() => Array(4).fill(0));

        // Each round key consists of 4 words
        for (let wordIndex = 0; wordIndex < 4; wordIndex++) {
            const word = words[round * 4 + wordIndex];

            // Fill column-wise
            for (let byteIndex = 0; byteIndex < 4; byteIndex++) {
                roundKey[byteIndex][wordIndex] = word[byteIndex];
            }
        }

        roundKeys.push(roundKey);
    }

    return {
        roundKeys,
        expansionDetails
    };
}

/**
 * Format round key as hex string for display
 * 
 * @param {number[][]} roundKey - 4x4 round key matrix
 * @returns {string} Formatted hex string
 */
export function formatRoundKey(roundKey) {
    return roundKey.map(row =>
        row.map(byte => byte.toString(16).padStart(2, '0')).join(' ')
    ).join('\n');
}
