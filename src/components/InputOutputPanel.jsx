import './InputOutputPanel.css';

/**
 * InputOutputPanel Component
 * 
 * Displays two side-by-side panels:
 * - Left: Input text (plain text for encryption, cipher for decryption)
 * - Right: Output text (cipher for encryption, plain text for decryption)
 * 
 * Includes a swap button to switch between encryption and decryption modes
 */
function InputOutputPanel({ mode, plainText, setPlainText, cipherText, setCipherText, onSwap }) {
    return (
        <div className="input-output-container">
            {/* Left Panel */}
            <div className="panel glass-effect">
                <div className="panel-header">
                    <h3 className="panel-title">
                        {mode === 'encrypt' ? '📝 Plain Text' : '🔐 Cipher Text (Hex)'}
                    </h3>
                </div>
                <div className="panel-body">
                    <textarea
                        className={`panel-textarea ${mode === 'decrypt' ? 'mono-font' : ''}`}
                        placeholder={mode === 'encrypt' ? 'Enter text to encrypt...' : 'Enter cipher text in hex...'}
                        value={mode === 'encrypt' ? plainText : cipherText}
                        onChange={(e) => mode === 'encrypt' ? setPlainText(e.target.value) : setCipherText(e.target.value)}
                    />
                </div>
            </div>

            {/* Swap Button */}
            <div className="swap-button-container">
                <button className="swap-button glass-effect" onClick={onSwap} title="Swap Input/Output">
                    <span className="swap-icon">⇄</span>
                </button>
            </div>

            {/* Right Panel */}
            <div className="panel glass-effect">
                <div className="panel-header">
                    <h3 className="panel-title">
                        {mode === 'encrypt' ? '🔐 Cipher Text (Hex)' : '📝 Plain Text'}
                    </h3>
                </div>
                <div className="panel-body">
                    <textarea
                        className={`panel-textarea ${mode === 'encrypt' ? 'mono-font' : ''}`}
                        placeholder={mode === 'encrypt' ? 'Cipher text will appear here...' : 'Decrypted text will appear here...'}
                        value={mode === 'encrypt' ? cipherText : plainText}
                        readOnly
                    />
                </div>
            </div>
        </div>
    );
}

export default InputOutputPanel;
