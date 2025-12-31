/**
 * AES-256 Encryption
 * 
 * This file implements the main encryption algorithm for AES-256.
 * It processes data in 128-bit (16-byte) blocks and applies 14 rounds of transformations.
 */

import { NUMBER_OF_ROUNDS } from './constants.js';
import {
    substituteBytes,
    shiftRows,
    mixColumns,
    addRoundKey
} from './transformations.js';
import {
    bytesToStateMatrix,
    stateMatrixToBytes,
    copyStateMatrix,
    formatStateMatrix,
    padData
} from './utils.js';
import { expandKey } from './keyExpansion.js';

// ====================================================================================
// BLOCK ENCRYPTION
// ====================================================================================

/**
 * Encrypt a single 128-bit (16-byte) block
 * 
 * @param {number[]} block - 16-byte block to encrypt
 * @param {number[][]} roundKeys - Array of round keys from key expansion
 * @param {boolean} trackRounds - Whether to track round-by-round details
 * @returns {Object} Object containing encrypted bytes and round details
 */
export function encryptBlock(block, roundKeys, trackRounds = false) {
    // Convert block to state matrix (4x4)
    let state = bytesToStateMatrix(block);

    // Array to store round details for visualization
    const roundDetails = [];

    if (trackRounds) {
        roundDetails.push({
            round: 0,
            step: 'Initial State',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // Initial round: AddRoundKey only
    state = addRoundKey(state, roundKeys[0]);

    if (trackRounds) {
        roundDetails.push({
            round: 0,
            step: 'After AddRoundKey',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state),
            roundKey: formatStateMatrix(roundKeys[0])
        });
    }

    // Main rounds (rounds 1 to NUMBER_OF_ROUNDS - 1)
    for (let round = 1; round < NUMBER_OF_ROUNDS; round++) {
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'Start of Round',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // SubBytes
        state = substituteBytes(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After SubBytes',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // ShiftRows
        state = shiftRows(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After ShiftRows',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // MixColumns
        state = mixColumns(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After MixColumns',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // AddRoundKey
        state = addRoundKey(state, roundKeys[round]);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After AddRoundKey',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state),
                roundKey: formatStateMatrix(roundKeys[round])
            });
        }
    }

    // Final round (round NUMBER_OF_ROUNDS): No MixColumns
    const finalRound = NUMBER_OF_ROUNDS;

    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'Start of Final Round',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // SubBytes
    state = substituteBytes(state);
    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'After SubBytes',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // ShiftRows
    state = shiftRows(state);
    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'After ShiftRows',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // AddRoundKey (final)
    state = addRoundKey(state, roundKeys[finalRound]);
    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'After AddRoundKey (Final)',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state),
            roundKey: formatStateMatrix(roundKeys[finalRound])
        });
    }

    // Convert state matrix back to bytes
    const encryptedBlock = stateMatrixToBytes(state);

    return {
        encryptedBlock,
        roundDetails
    };
}

// ====================================================================================
// TEXT ENCRYPTION
// ====================================================================================

/**
 * Encrypt plain text using AES-256
 * 
 * @param {number[]} plainBytes - Plain text as byte array
 * @param {number[]} key - 32-byte encryption key
 * @param {boolean} trackRounds - Whether to track round-by-round details
 * @returns {Object} Object containing:
 *   - cipherBytes: Encrypted data as byte array
 *   - roundDetails: Details of each round (if trackRounds is true)
 *   - keyExpansion: Details of key expansion
 *   - completeCipherPerRound: Complete cipher text after each round (if trackRounds is true)
 */
export function encryptText(plainBytes, key, trackRounds = false) {
    // Pad the data to a multiple of 16 bytes
    const paddedData = padData(plainBytes);

    // Expand the key
    const { roundKeys, expansionDetails } = expandKey(key);

    // Array to hold all cipher blocks
    const cipherBytes = [];

    // Array to hold round details for first block
    let allRoundDetails = [];

    // Array to track complete cipher text after each round (for all blocks)
    const completeCipherPerRound = trackRounds ? {} : null;

    if (trackRounds) {
        // Process all blocks round by round to track complete cipher text
        const numBlocks = paddedData.length / 16;
        const blockStates = [];

        // Initialize block states
        for (let i = 0; i < numBlocks; i++) {
            const block = paddedData.slice(i * 16, (i + 1) * 16);
            blockStates.push(bytesToStateMatrix(block));
        }

        // Track complete cipher text after round 0 (initial AddRoundKey)
        for (let i = 0; i < numBlocks; i++) {
            blockStates[i] = addRoundKey(blockStates[i], roundKeys[0]);
        }
        let fullCipher = [];
        blockStates.forEach(state => fullCipher.push(...stateMatrixToBytes(state)));
        completeCipherPerRound[0] = fullCipher;

        // Process all main rounds (1 to 13)
        for (let round = 1; round < NUMBER_OF_ROUNDS; round++) {
            for (let i = 0; i < numBlocks; i++) {
                blockStates[i] = substituteBytes(blockStates[i]);
                blockStates[i] = shiftRows(blockStates[i]);
                blockStates[i] = mixColumns(blockStates[i]);
                blockStates[i] = addRoundKey(blockStates[i], roundKeys[round]);
            }
            // Collect complete cipher text after this round
            fullCipher = [];
            blockStates.forEach(state => fullCipher.push(...stateMatrixToBytes(state)));
            completeCipherPerRound[round] = fullCipher;
        }

        // Final round (14)
        const finalRound = NUMBER_OF_ROUNDS;
        for (let i = 0; i < numBlocks; i++) {
            blockStates[i] = substituteBytes(blockStates[i]);
            blockStates[i] = shiftRows(blockStates[i]);
            blockStates[i] = addRoundKey(blockStates[i], roundKeys[finalRound]);
        }
        // Collect complete cipher text after final round
        fullCipher = [];
        blockStates.forEach(state => fullCipher.push(...stateMatrixToBytes(state)));
        completeCipherPerRound[finalRound] = fullCipher;

        // Set final cipher bytes
        cipherBytes.push(...fullCipher);
    } else {
        // Normal processing without tracking
        for (let i = 0; i < paddedData.length; i += 16) {
            const block = paddedData.slice(i, i + 16);
            const { encryptedBlock } = encryptBlock(block, roundKeys, false);
            cipherBytes.push(...encryptedBlock);
        }
    }

    // Get round details for first block only (for state matrix visualization)
    if (trackRounds) {
        const firstBlock = paddedData.slice(0, 16);
        const { roundDetails } = encryptBlock(firstBlock, roundKeys, true);
        allRoundDetails = roundDetails;
    }

    return {
        cipherBytes,
        roundDetails: allRoundDetails,
        completeCipherPerRound,
        keyExpansion: {
            roundKeys: roundKeys.map(rk => formatStateMatrix(rk)),
            expansionDetails
        }
    };
}
