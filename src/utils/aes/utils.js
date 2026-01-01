/**
 * AES Utility Functions
 * 
 * This file contains helper functions for data conversion, padding, and key generation.
 * These utilities bridge the gap between user input (text/hex strings) and the
 * byte arrays that the AES algorithm operates on.
 */

import { BLOCK_SIZE } from './constants.js';

// ====================================================================================
// TEXT AND BYTE CONVERSION
// ====================================================================================

/**
 * Convert a text string to an array of bytes (UTF-8 encoding)
 * 
 * @param {string} text - The text string to convert
 * @returns {number[]} Array of bytes representing the text
 */
export function textToBytes(text) {
    const encoder = new TextEncoder();
    return Array.from(encoder.encode(text));
}

/**
 * Convert an array of bytes to a text string (UTF-8 decoding)
 * 
 * @param {number[]} bytes - Array of bytes to convert
 * @returns {string} The decoded text string
 */
export function bytesToText(bytes) {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

// ====================================================================================
// HEX CONVERSION
// ====================================================================================

/**
 * Convert an array of bytes to a hexadecimal string
 * Each byte is represented as two hex digits (e.g., 0x0F becomes "0f")
 * 
 * @param {number[]} bytes - Array of bytes to convert
 * @returns {string} Hexadecimal string representation
 */
export function bytesToHex(bytes) {
    return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert a hexadecimal string to an array of bytes
 * Every two characters in the hex string represent one byte
 * 
 * @param {string} hexString - Hexadecimal string to convert
 * @returns {number[]} Array of bytes
 */
export function hexToBytes(hexString) {
    const bytes = [];
    // Remove any spaces or non-hex characters
    const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');

    // Process two characters at a time
    for (let i = 0; i < cleanHex.length; i += 2) {
        bytes.push(parseInt(cleanHex.substr(i, 2), 16));
    }

    return bytes;
}

// ====================================================================================
// PADDING
// ====================================================================================

/**
 * Add padding to data
 * Padding adds N bytes of value N to make the data a multiple of the block size
 * For example, if 5 bytes of padding are needed, add five bytes each with value 0x05
 * 
 * @param {number[]} data - Data to pad
 * @returns {number[]} Padded data
 */
export function padData(data) {
    // Calculate how many bytes we need to add to reach a multiple of BLOCK_SIZE
    const paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);

    // Create new array with original data plus padding
    const paddedData = [...data];

    // Add padding bytes (each byte has the value of the padding length)
    for (let i = 0; i < paddingLength; i++) {
        paddedData.push(paddingLength);
    }

    return paddedData;
}

/**
 * Remove padding from data
 * Reads the last byte to determine how many padding bytes to remove
 * 
 * @param {number[]} data - Padded data
 * @returns {number[]} Unpadded data
 */
export function unpadData(data) {
    if (data.length === 0) {
        return data;
    }

    // The last byte tells us how many padding bytes there are
    const paddingLength = data[data.length - 1];

    // Validate padding
    if (paddingLength > BLOCK_SIZE || paddingLength === 0) {
        throw new Error('Invalid padding');
    }

    // Verify that all padding bytes have the correct value
    for (let i = 1; i <= paddingLength; i++) {
        if (data[data.length - i] !== paddingLength) {
            throw new Error('Invalid padding');
        }
    }

    // Remove padding bytes
    return data.slice(0, data.length - paddingLength);
}

// ====================================================================================
// KEY GENERATION
// ====================================================================================

/**
 * Generate a 256-bit (32 byte) key from a passphrase
 * This uses a simple SHA-256-like approach for educational purposes
 * 
 * @param {string} passphrase - User's passphrase
 * @returns {number[]} 32-byte key array
 */
export async function generateKeyFromPassphrase(passphrase) {
    // Convert passphrase to bytes
    const encoder = new TextEncoder();
    const passphraseBytes = encoder.encode(passphrase);

    // Use Web Crypto API to hash the passphrase
    const hashBuffer = await crypto.subtle.digest('SHA-256', passphraseBytes);

    // Convert to byte array
    return Array.from(new Uint8Array(hashBuffer));
}

// ====================================================================================
// STATE MATRIX OPERATIONS
// ====================================================================================

/**
 * Convert a flat byte array to a 4x4 state matrix (column-major order)
 * AES processes data in 4x4 matrices where each cell is one byte
 * The bytes are filled column by column
 * 
 * @param {number[]} bytes - 16-byte array
 * @returns {number[][]} 4x4 state matrix
 */
export function bytesToStateMatrix(bytes) {
    const state = Array(4).fill(null).map(() => Array(4).fill(0));

    for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
            state[row][col] = bytes[col * 4 + row];
        }
    }

    return state;
}

/**
 * Convert a 4x4 state matrix back to a flat byte array (column-major order)
 * 
 * @param {number[][]} state - 4x4 state matrix
 * @returns {number[]} 16-byte array
 */
export function stateMatrixToBytes(state) {
    const bytes = [];

    for (let col = 0; col < 4; col++) {
        for (let row = 0; row < 4; row++) {
            bytes.push(state[row][col]);
        }
    }

    return bytes;
}

/**
 * Create a deep copy of a state matrix
 * 
 * @param {number[][]} state - State matrix to copy
 * @returns {number[][]} Deep copy of the state matrix
 */
export function copyStateMatrix(state) {
    return state.map(row => [...row]);
}

/**
 * Format a state matrix as a readable hex string for debugging/display
 * 
 * @param {number[][]} state - State matrix to format
 * @returns {string} Formatted hex string
 */
export function formatStateMatrix(state) {
    return state.map(row =>
        row.map(byte => byte.toString(16).padStart(2, '0')).join(' ')
    ).join('\n');
}
