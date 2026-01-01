import './KeyInput.css';

/**
 * KeyInput Component
 * 
 * Allows the user to enter a passphrase for encryption/decryption
 * Displays the generated 256-bit key in hexadecimal format
 */
function KeyInput({ passphrase, setPassphrase, keyHex }) {
    return (
        <div className="key-input-container glass-effect">
            <h2 className="key-input-title">
                Encryption Key
            </h2>

            <div className="key-input-group">
                <label htmlFor="passphrase" className="input-label">
                    Passphrase
                </label>
                <input
                    id="passphrase"
                    type="text"
                    placeholder="Enter your passphrase..."
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    className="passphrase-input"
                />
            </div>

            {keyHex && (
                <div className="key-display">
                    <label className="input-label">Generated 256-bit Key (Hex)</label>
                    <div className="key-hex mono-font">
                        {keyHex}
                    </div>
                </div>
            )}
        </div>
    );
}

export default KeyInput;
