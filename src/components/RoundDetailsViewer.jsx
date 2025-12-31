import { useState } from 'react';
import './RoundDetailsViewer.css';

/**
 * RoundDetailsViewer Component
 * 
 * Displays round-by-round details of the AES encryption/decryption process:
 * - Complete cipher text after each round (for all blocks)
 * - Round keys from key expansion
 * - State transformations at each step
 * - Intermediate values for each round
 */
function RoundDetailsViewer({ roundDetails, keyExpansion, completeCipherPerRound, mode }) {
    const [expandedRounds, setExpandedRounds] = useState({});
    const [showKeyExpansion, setShowKeyExpansion] = useState(false);

    // Helper function to format bytes to hex with spaces every 32 chars (2 blocks)
    const formatCipherText = (bytes) => {
        if (!bytes) return '';
        const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
        // Add space every 32 characters (one block = 16 bytes = 32 hex chars)
        return hex.match(/.{1,32}/g)?.join(' ') || hex;
    };

    const toggleRound = (index) => {
        setExpandedRounds(prev => ({
            ...prev,
            [index]: !prev[index]
        }));
    };

    const toggleAllRounds = () => {
        const allExpanded = Object.keys(expandedRounds).length === roundDetails.length &&
            Object.values(expandedRounds).every(v => v);

        if (allExpanded) {
            setExpandedRounds({});
        } else {
            const newExpanded = {};
            roundDetails.forEach((_, index) => {
                newExpanded[index] = true;
            });
            setExpandedRounds(newExpanded);
        }
    };

    // Group round details by round number
    const groupedByRound = roundDetails.reduce((acc, detail, index) => {
        if (!acc[detail.round]) {
            acc[detail.round] = [];
        }
        acc[detail.round].push({ ...detail, originalIndex: index });
        return acc;
    }, {});

    return (
        <div className="round-details-container glass-effect">
            <div className="round-details-header">
                <h2 className="round-details-title">
                    <span className="icon">📊</span>
                    Round-by-Round Details ({mode === 'encrypt' ? 'Encryption' : 'Decryption'})
                </h2>
                <div className="round-details-controls">
                    <button
                        className="control-btn"
                        onClick={toggleAllRounds}
                    >
                        {Object.values(expandedRounds).every(v => v) ? 'Collapse All' : 'Expand All'}
                    </button>
                    <button
                        className="control-btn"
                        onClick={() => setShowKeyExpansion(!showKeyExpansion)}
                    >
                        {showKeyExpansion ? 'Hide' : 'Show'} Key Expansion
                    </button>
                </div>
            </div>

            {/* Key Expansion Section */}
            {showKeyExpansion && keyExpansion && (
                <div className="key-expansion-section">
                    <h3 className="section-title">Round Keys</h3>
                    <div className="round-keys-grid">
                        {keyExpansion.roundKeys.map((key, index) => (
                            <div key={index} className="round-key-item">
                                <div className="round-key-label">Round {index}</div>
                                <pre className="round-key-matrix mono-font">{key}</pre>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Round Details Section */}
            <div className="rounds-section">
                {Object.entries(groupedByRound).map(([roundNum, steps]) => (
                    <div key={roundNum} className="round-group">
                        <button
                            className="round-header"
                            onClick={() => toggleRound(roundNum)}
                        >
                            <span className="round-number">
                                Round {roundNum} {roundNum === '0' && '(Initial)'}
                                {roundNum === '14' && '(Final)'}
                            </span>
                            <span className="expand-icon">
                                {expandedRounds[roundNum] ? '▼' : '▶'}
                            </span>
                        </button>

                        {/* Complete Cipher Text after this round */}
                        {completeCipherPerRound && completeCipherPerRound[roundNum] && (
                            <div className="complete-cipher-section">
                                <div className="cipher-label">
                                    📝 Complete {mode === 'encrypt' ? 'Cipher' : 'Plain'} Text After Round {roundNum}:
                                </div>
                                <div className="cipher-text-display mono-font">
                                    {formatCipherText(completeCipherPerRound[roundNum])}
                                </div>
                                <div className="cipher-info">
                                    {completeCipherPerRound[roundNum].length} bytes ({completeCipherPerRound[roundNum].length / 16} blocks)
                                </div>
                            </div>
                        )}

                        {expandedRounds[roundNum] && (
                            <div className="round-steps">
                                {steps.map((step, stepIndex) => (
                                    <div key={stepIndex} className="step-item">
                                        <div className="step-header">
                                            <span className="step-name">{step.step}</span>
                                        </div>
                                        <div className="step-content">
                                            <div className="state-matrix-container">
                                                <div className="matrix-label">State Matrix (First Block):</div>
                                                <pre className="state-matrix mono-font">{step.state}</pre>
                                            </div>
                                            {step.roundKey && (
                                                <div className="state-matrix-container">
                                                    <div className="matrix-label">Round Key:</div>
                                                    <pre className="state-matrix mono-font">{step.roundKey}</pre>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </div>
    );
}

export default RoundDetailsViewer;
