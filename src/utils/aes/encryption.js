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
 */
export function encryptText(plainBytes, key, trackRounds = false) {
    // Pad the data to a multiple of 16 bytes
    const paddedData = padData(plainBytes);

    // Expand the key
    const { roundKeys, expansionDetails } = expandKey(key);

    // Array to hold all cipher blocks
    const cipherBytes = [];

    // Array to hold round details for all blocks (only track first block to avoid overwhelming data)
    let allRoundDetails = [];

    // Process each 16-byte block
    for (let i = 0; i < paddedData.length; i += 16) {
        const block = paddedData.slice(i, i + 16);

        // Only track rounds for the first block to keep data manageable
        const shouldTrack = trackRounds && (i === 0);

        const { encryptedBlock, roundDetails } = encryptBlock(block, roundKeys, shouldTrack);

        // Add encrypted block to result
        cipherBytes.push(...encryptedBlock);

        // Store round details only for first block
        if (shouldTrack) {
            allRoundDetails = roundDetails;
        }
    }

    return {
        cipherBytes,
        roundDetails: allRoundDetails,
        keyExpansion: {
            roundKeys: roundKeys.map(rk => formatStateMatrix(rk)),
            expansionDetails
        }
    };
}
