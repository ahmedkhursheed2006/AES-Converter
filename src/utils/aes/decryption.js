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
 *   - completeCipherPerRound: Complete plain text after each round (if trackRounds is true)
 */
export function decryptText(cipherBytes, key, trackRounds = false) {
    // Expand the key
    const { roundKeys, expansionDetails } = expandKey(key);

    // Array to hold all decrypted blocks
    let plainBytes = [];

    // Array to hold round details for first block
    let allRoundDetails = [];

    // Array to track complete plain text after each round (for all blocks)
    const completeCipherPerRound = trackRounds ? {} : null;

    if (trackRounds) {
        // Process all blocks round by round to track complete plain text
        const numBlocks = cipherBytes.length / 16;
        const blockStates = [];

        // Initialize block states
        for (let i = 0; i < numBlocks; i++) {
            const block = cipherBytes.slice(i * 16, (i + 1) * 16);
            blockStates.push(bytesToStateMatrix(block));
        }

        // Track complete plain text after round 14 (initial AddRoundKey)
        for (let i = 0; i < numBlocks; i++) {
            blockStates[i] = addRoundKey(blockStates[i], roundKeys[NUMBER_OF_ROUNDS]);
        }
        let fullPlain = [];
        blockStates.forEach(state => fullPlain.push(...stateMatrixToBytes(state)));
        completeCipherPerRound[NUMBER_OF_ROUNDS] = fullPlain;

        // Process all main rounds (13 down to 1)
        for (let round = NUMBER_OF_ROUNDS - 1; round >= 1; round--) {
            for (let i = 0; i < numBlocks; i++) {
                blockStates[i] = inverseShiftRows(blockStates[i]);
                blockStates[i] = inverseSubstituteBytes(blockStates[i]);
                blockStates[i] = addRoundKey(blockStates[i], roundKeys[round]);
                blockStates[i] = inverseMixColumns(blockStates[i]);
            }
            // Collect complete plain text after this round
            fullPlain = [];
            blockStates.forEach(state => fullPlain.push(...stateMatrixToBytes(state)));
            completeCipherPerRound[round] = fullPlain;
        }

        // Final round (0)
        const finalRound = 0;
        for (let i = 0; i < numBlocks; i++) {
            blockStates[i] = inverseShiftRows(blockStates[i]);
            blockStates[i] = inverseSubstituteBytes(blockStates[i]);
            blockStates[i] = addRoundKey(blockStates[i], roundKeys[finalRound]);
        }
        // Collect complete plain text after final round
        fullPlain = [];
        blockStates.forEach(state => fullPlain.push(...stateMatrixToBytes(state)));
        completeCipherPerRound[finalRound] = fullPlain;

        // Set final plain bytes (with padding removed)
        plainBytes = unpadData(fullPlain);
    } else {
        // Normal processing without tracking
        const tempPlainBytes = [];
        for (let i = 0; i < cipherBytes.length; i += 16) {
            const block = cipherBytes.slice(i, i + 16);
            const { decryptedBlock } = decryptBlock(block, roundKeys, false);
            tempPlainBytes.push(...decryptedBlock);
        }
        plainBytes = unpadData(tempPlainBytes);
    }

    // Get round details for first block only (for state matrix visualization)
    if (trackRounds) {
        const firstBlock = cipherBytes.slice(0, 16);
        const { roundDetails } = decryptBlock(firstBlock, roundKeys, true);
        allRoundDetails = roundDetails;
    }

    return {
        plainBytes,
        roundDetails: allRoundDetails,
        completeCipherPerRound,
        keyExpansion: {
            roundKeys: roundKeys.map(rk => formatStateMatrix(rk)),
            expansionDetails
        }
    };
}
