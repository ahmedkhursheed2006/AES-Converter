# AES-256 Encryption Web Application

An educational React-based implementation of the AES-256 (Advanced Encryption Standard) encryption algorithm with visual round-by-round tracking and a modern, interactive user interface.

> ⚠️ **Educational Purpose Only**: This implementation is for learning and understanding AES-256. For production use, always rely on established cryptographic libraries.

## Features

- ✨ **Complete AES-256 Implementation** - Built from scratch without built-in crypto functions
- 🎨 **Modern UI** - Beautiful glassmorphism design with dark mode
- 🔄 **Bidirectional** - Encrypt and decrypt with easy mode switching
- 📊 **Round Visualization** - View detailed state transformations for each round
- 🔑 **Key Expansion Display** - See all generated round keys
- 🎯 **Real-time Processing** - Instant encryption/decryption as you type
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Usage

1. **Enter a Passphrase** - Type any passphrase to generate a 256-bit encryption key
2. **Input Text** - Enter plain text (in encrypt mode) or hex cipher text (in decrypt mode)
3. **View Results** - Output appears automatically on the right panel
4. **Toggle Round Details** - Click "Show Round Details" to see the encryption process step-by-step
5. **Switch Modes** - Click the swap button or mode toggle to switch between encryption and decryption
6. **Clear All** - Reset all inputs and outputs with the Clear button

## Project Structure

```
src/
├── components/          # React UI components
│   ├── KeyInput.jsx           # Passphrase input and key display
│   ├── ControlPanel.jsx       # Mode controls and action buttons
│   ├── InputOutputPanel.jsx   # Text input/output panels
│   └── RoundDetailsViewer.jsx # Round-by-round visualization
│
├── utils/aes/          # AES-256 algorithm implementation
│   ├── constants.js           # S-Box, Inverse S-Box, Rcon
│   ├── galoisField.js         # GF(2^8) arithmetic operations
│   ├── utils.js               # Helper functions (conversion, padding)
│   ├── transformations.js     # Core AES transformations
│   ├── keyExpansion.js        # Key schedule algorithm
│   ├── encryption.js          # Encryption functions
│   └── decryption.js          # Decryption functions
│
├── App.jsx             # Main application component
├── index.css           # Global styles and design system
└── main.jsx            # Application entry point
```

## AES-256 Algorithm Components

### Core Constants (`constants.js`)

- **S-Box** - Substitution box for SubBytes transformation
- **Inverse S-Box** - Reverse substitution for InvSubBytes
- **Round Constants (Rcon)** - Used in key expansion
- **Configuration** - Block size, key size, number of rounds

### Galois Field Operations (`galoisField.js`)

Functions for GF(2^8) multiplication used in MixColumns:
- `multiplyByTwo(byte)` - Multiply by 2 in GF(2^8)
- `multiplyByThree(byte)` - Multiply by 3 in GF(2^8)
- `galoisMultiply(a, b)` - General multiplication in GF(2^8)
- `multiplyByNine(byte)` - For InvMixColumns
- `multiplyByEleven(byte)` - For InvMixColumns
- `multiplyByThirteen(byte)` - For InvMixColumns
- `multiplyByFourteen(byte)` - For InvMixColumns

### Utility Functions (`utils.js`)

**Conversion Functions:**
- `textToBytes(text)` - Convert UTF-8 text to byte array
- `bytesToText(bytes)` - Convert byte array to UTF-8 text
- `bytesToHex(bytes)` - Convert bytes to hexadecimal string
- `hexToBytes(hexString)` - Convert hexadecimal string to bytes

**Padding Functions:**
- `padData(data)` - Add PKCS#7 padding
- `unpadData(data)` - Remove PKCS#7 padding

**Key Generation:**
- `generateKeyFromPassphrase(passphrase)` - Generate 256-bit key from passphrase using SHA-256

**State Matrix Operations:**
- `bytesToStateMatrix(bytes)` - Convert bytes to 4x4 state matrix
- `stateMatrixToBytes(state)` - Convert state matrix back to bytes
- `copyStateMatrix(state)` - Deep copy state matrix
- `formatStateMatrix(state)` - Format matrix for display

### AES Transformations (`transformations.js`)

**Forward Transformations (Encryption):**
- `substituteBytes(state)` - Apply S-Box substitution to each byte
- `shiftRows(state)` - Cyclically shift rows left
- `mixColumns(state)` - Mix columns using GF multiplication
- `addRoundKey(state, roundKey)` - XOR state with round key

**Inverse Transformations (Decryption):**
- `inverseSubstituteBytes(state)` - Apply Inverse S-Box
- `inverseShiftRows(state)` - Shift rows right
- `inverseMixColumns(state)` - Inverse column mixing

### Key Expansion (`keyExpansion.js`)

- `expandKey(key)` - Expand 256-bit key into 15 round keys
  - **Parameters:** 32-byte key array
  - **Returns:** Object with `roundKeys` (array of 15 4x4 matrices) and `expansionDetails` (step-by-step details)

**Helper Functions:**
- `rotateWord(word)` - Rotate 4-byte word left by one
- `substituteWord(word)` - Apply S-Box to each byte in word
- `xorWords(word1, word2)` - XOR two words

### Encryption (`encryption.js`)

**Main Functions:**
- `encryptBlock(block, roundKeys, trackRounds)`
  - **Parameters:** 16-byte block, round keys array, tracking flag
  - **Returns:** Encrypted block and round details
  
- `encryptText(plainBytes, key, trackRounds)`
  - **Parameters:** Plain text bytes, 32-byte key, tracking flag
  - **Returns:** Cipher bytes, round details, key expansion details

**Process:**
1. Initial AddRoundKey
2. 13 main rounds (SubBytes → ShiftRows → MixColumns → AddRoundKey)
3. Final round (SubBytes → ShiftRows → AddRoundKey, no MixColumns)

### Decryption (`decryption.js`)

**Main Functions:**
- `decryptBlock(block, roundKeys, trackRounds)`
  - **Parameters:** 16-byte cipher block, round keys array, tracking flag
  - **Returns:** Decrypted block and round details
  
- `decryptText(cipherBytes, key, trackRounds)`
  - **Parameters:** Cipher bytes, 32-byte key, tracking flag
  - **Returns:** Plain bytes, round details, key expansion details

**Process:**
1. Initial AddRoundKey (with round 14 key)
2. 13 main rounds (InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns)
3. Final round (InvShiftRows → InvSubBytes → AddRoundKey, no InvMixColumns)

## React Components

### App.jsx
Main application component managing:
- Encryption/decryption mode state
- Input/output text state
- Passphrase and key generation
- Round details visibility
- Error handling

### KeyInput.jsx
- Passphrase input field
- Generated key display (hex format)
- Visual feedback

### ControlPanel.jsx
- Encrypt/Decrypt mode toggle
- Show/Hide round details toggle
- Clear all button

### InputOutputPanel.jsx
- Dual text areas for input/output
- Swap button to exchange panels
- Automatic mode switching

### RoundDetailsViewer.jsx
- Collapsible round groups
- State matrix display for each step
- Round key visualization
- Key expansion display
- Expand/collapse all controls

## Technical Details

### AES-256 Specification
- **Block Size:** 128 bits (16 bytes)
- **Key Size:** 256 bits (32 bytes)
- **Number of Rounds:** 14
- **Padding:** PKCS#7

### Algorithm Flow

**Encryption:**
```
1. Key Expansion (32 bytes → 15 round keys)
2. Add Padding (PKCS#7)
3. For each 16-byte block:
   a. Initial Round: AddRoundKey
   b. Rounds 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
   c. Final Round: SubBytes → ShiftRows → AddRoundKey
4. Output cipher text in hex
```

**Decryption:**
```
1. Key Expansion (same as encryption)
2. For each 16-byte block:
   a. Initial Round: AddRoundKey (round 14)
   b. Rounds 13-1: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
   c. Final Round: InvShiftRows → InvSubBytes → AddRoundKey
3. Remove Padding (PKCS#7)
4. Output plain text
```

## Design System

### Color Palette
- **Background:** Deep navy gradients (#0a0e27 → #121632)
- **Accents:** Vibrant purple-pink gradients (#6366f1 → #8b5cf6 → #ec4899)
- **Text:** Light gray scales for optimal readability

### Typography
- **UI Font:** Inter (sans-serif)
- **Code Font:** Fira Code (monospace)

### Effects
- Glassmorphism panels with backdrop blur
- Smooth transitions and micro-animations
- Gradient text for headings
- Glow effects on interactive elements

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

Requires support for:
- Web Crypto API (for SHA-256 hashing)
- CSS backdrop-filter
- ES6+ JavaScript features

## License

This project is for educational purposes. Feel free to use and modify for learning.

## Contributing

This is an educational project. Contributions for improving code clarity, adding comments, or enhancing the UI are welcome!

---

Built with ❤️ for learning cryptography
