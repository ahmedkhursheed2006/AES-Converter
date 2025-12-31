/**
 * AES-256 Decryption
 * 
 * This file implements the decryption algorithm for AES-256.
 * It reverses the encryption process by applying inverse transformations
 * in reverse order.
 */

import { NUMBER_OF_ROUNDS } from './constants.js';
import {
    inverseSubstituteBytes,
    inverseShiftRows,
    inverseMixColumns,
    addRoundKey
} from './transformations.js';
import {
    bytesToStateMatrix,
    stateMatrixToBytes,
    copyStateMatrix,
    formatStateMatrix,
    unpadData
} from './utils.js';
import { expandKey } from './keyExpansion.js';

// ====================================================================================
// BLOCK DECRYPTION
// ====================================================================================

/**
 * Decrypt a single 128-bit (16-byte) block
 * 
 * @param {number[]} block - 16-byte block to decrypt
 * @param {number[][]} roundKeys - Array of round keys from key expansion
 * @param {boolean} trackRounds - Whether to track round-by-round details
 * @returns {Object} Object containing decrypted bytes and round details
 */
export function decryptBlock(block, roundKeys, trackRounds = false) {
    // Convert block to state matrix (4x4)
    let state = bytesToStateMatrix(block);

    // Array to store round details for visualization
    const roundDetails = [];

    if (trackRounds) {
        roundDetails.push({
            round: NUMBER_OF_ROUNDS,
            step: 'Initial State (Cipher)',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // Initial round: AddRoundKey with the LAST round key
    state = addRoundKey(state, roundKeys[NUMBER_OF_ROUNDS]);

    if (trackRounds) {
        roundDetails.push({
            round: NUMBER_OF_ROUNDS,
            step: 'After AddRoundKey',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state),
            roundKey: formatStateMatrix(roundKeys[NUMBER_OF_ROUNDS])
        });
    }

    // Main rounds (rounds NUMBER_OF_ROUNDS - 1 down to 1)
    for (let round = NUMBER_OF_ROUNDS - 1; round >= 1; round--) {
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'Start of Round',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // InverseShiftRows
        state = inverseShiftRows(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After InverseShiftRows',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }

        // InverseSubBytes
        state = inverseSubstituteBytes(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After InverseSubBytes',
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

        // InverseMixColumns (not in final round)
        state = inverseMixColumns(state);
        if (trackRounds) {
            roundDetails.push({
                round,
                step: 'After InverseMixColumns',
                state: formatStateMatrix(state),
                stateMatrix: copyStateMatrix(state)
            });
        }
    }

    // Final round (round 0): No InverseMixColumns
    const finalRound = 0;

    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'Start of Final Round',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // InverseShiftRows
    state = inverseShiftRows(state);
    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'After InverseShiftRows',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // InverseSubBytes
    state = inverseSubstituteBytes(state);
    if (trackRounds) {
        roundDetails.push({
            round: finalRound,
            step: 'After InverseSubBytes',
            state: formatStateMatrix(state),
            stateMatrix: copyStateMatrix(state)
        });
    }

    // AddRoundKey (final, with round key 0)
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
    const decryptedBlock = stateMatrixToBytes(state);

    return {
        decryptedBlock,
        roundDetails
    };
}

// ====================================================================================
// TEXT DECRYPTION
// ====================================================================================

/**
 * Decrypt cipher text using AES-256
 * 
 * @param {number[]} cipherBytes - Cipher text as byte array
 * @param {number[]} key - 32-byte decryption key
 * @param {boolean} trackRounds - Whether to track round-by-round details
 * @returns {Object} Object containing:
 *   - plainBytes: Decrypted data as byte array
 *   - roundDetails: Details of each round (if trackRounds is true)
 *   - keyExpansion: Details of key expansion
 */
export function decryptText(cipherBytes, key, trackRounds = false) {
    // Expand the key
    const { roundKeys, expansionDetails } = expandKey(key);

    // Array to hold all decrypted blocks
    const plainBytes = [];

    // Array to hold round details for all blocks (only track first block to avoid overwhelming data)
    let allRoundDetails = [];

    // Process each 16-byte block
    for (let i = 0; i < cipherBytes.length; i += 16) {
        const block = cipherBytes.slice(i, i + 16);

        // Only track rounds for the first block to keep data manageable
        const shouldTrack = trackRounds && (i === 0);

        const { decryptedBlock, roundDetails } = decryptBlock(block, roundKeys, shouldTrack);

        // Add decrypted block to result
        plainBytes.push(...decryptedBlock);

        // Store round details only for first block
        if (shouldTrack) {
            allRoundDetails = roundDetails;
        }
    }

    // Remove padding
    const unpaddedData = unpadData(plainBytes);

    return {
        plainBytes: unpaddedData,
        roundDetails: allRoundDetails,
        keyExpansion: {
            roundKeys: roundKeys.map(rk => formatStateMatrix(rk)),
            expansionDetails
        }
    };
}
