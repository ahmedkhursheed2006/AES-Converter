import './App.css';
import { useState, useEffect } from 'react';
import InputOutputPanel from './components/InputOutputPanel';
import KeyInput from './components/KeyInput';
import ControlPanel from './components/ControlPanel';
import RoundDetailsViewer from './components/RoundDetailsViewer';
import {
  textToBytes,
  bytesToText,
  bytesToHex,
  hexToBytes,
  generateKeyFromPassphrase
} from './utils/aes/utils';
import { encryptText } from './utils/aes/encryption';
import { decryptText } from './utils/aes/decryption';

function App() {
  // State for encryption/decryption mode
  const [mode, setMode] = useState('encrypt'); // 'encrypt' or 'decrypt'

  // State for input/output
  const [plainText, setPlainText] = useState('Sir Niaz will give us A Grade');
  const [cipherText, setCipherText] = useState('');

  // State for key
  const [passphrase, setPassphrase] = useState('Sir Niaz is Love');
  const [key, setKey] = useState(null);

  // State for round details
  const [showRoundDetails, setShowRoundDetails] = useState(false);
  const [roundDetails, setRoundDetails] = useState(null);
  const [keyExpansionDetails, setKeyExpansionDetails] = useState(null);
  const [completeCipherPerRound, setCompleteCipherPerRound] = useState(null);

  // State for errors
  const [error, setError] = useState('');

  // Generate key from passphrase whenever it changes
  useEffect(() => {
    if (passphrase) {
      generateKeyFromPassphrase(passphrase).then(generatedKey => {
        setKey(generatedKey);
      });
    } else {
      setKey(null);
    }
  }, [passphrase]);

  // Perform encryption/decryption when inputs change
  useEffect(() => {
    if (!key) {
      setError('Please enter a passphrase');
      return;
    }

    setError('');

    try {
      if (mode === 'encrypt' && plainText) {
        // Encrypt the plain text
        const plainBytes = textToBytes(plainText);
        const result = encryptText(plainBytes, key, showRoundDetails);

        // Set cipher text as hex
        setCipherText(bytesToHex(result.cipherBytes));

        if (showRoundDetails) {
          setRoundDetails(result.roundDetails);
          setKeyExpansionDetails(result.keyExpansion);
          setCompleteCipherPerRound(result.completeCipherPerRound);
        }
      } else if (mode === 'decrypt' && cipherText) {
        // Decrypt the cipher text
        try {
          const cipherBytes = hexToBytes(cipherText);
          const result = decryptText(cipherBytes, key, showRoundDetails);

          // Set plain text
          setPlainText(bytesToText(result.plainBytes));

          if (showRoundDetails) {
            setRoundDetails(result.roundDetails);
            setKeyExpansionDetails(result.keyExpansion);
            setCompleteCipherPerRound(result.completeCipherPerRound);
          }
        } catch (err) {
          setError('Invalid cipher text or key');
        }
      }
    } catch (err) {
      setError(err.message || 'An error occurred');
    }
  }, [mode, plainText, cipherText, key, showRoundDetails]);

  // Handle mode switch
  const handleModeSwitch = () => {
    setMode(mode === 'encrypt' ? 'decrypt' : 'encrypt');
  };

  // Handle input/output swap
  const handleSwap = () => {
    const temp = plainText;
    setPlainText(cipherText);
    setCipherText(temp);
    setMode(mode === 'encrypt' ? 'decrypt' : 'encrypt');
  };

  // Handle clear
  const handleClear = () => {
    setPlainText('');
    setCipherText('');
    setPassphrase('');
    setKey(null);
    setRoundDetails(null);
    setKeyExpansionDetails(null);
    setCompleteCipherPerRound(null);
    setError('');
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <h1 className="gradient-text">AES-256 Encryption</h1>
        <p className="app-subtitle">Advanced Encryption Standard with Round Visualization</p>
      </header>

      {/* Main Content */}
      <main className="app-main">
        {/* Key Input Section */}
        <KeyInput
          passphrase={passphrase}
          setPassphrase={setPassphrase}
          keyHex={key ? bytesToHex(key) : ''}
        />

        {/* Control Panel */}
        <ControlPanel
          mode={mode}
          onModeSwitch={handleModeSwitch}
          showRoundDetails={showRoundDetails}
          onToggleRoundDetails={() => setShowRoundDetails(!showRoundDetails)}
          onClear={handleClear}
        />

        {/* Error Display */}
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        {/* Input/Output Panels */}
        <InputOutputPanel
          mode={mode}
          plainText={plainText}
          setPlainText={setPlainText}
          cipherText={cipherText}
          setCipherText={setCipherText}
          onSwap={handleSwap}
        />

        {/* Round Details Viewer */}
        {showRoundDetails && roundDetails && (
          <RoundDetailsViewer
            roundDetails={roundDetails}
            keyExpansion={keyExpansionDetails}
            completeCipherPerRound={completeCipherPerRound}
            mode={mode}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <p>Educational Implementation of AES-256 • Not for Production Use</p>
      </footer>
    </div>
  );
}

export default App;
