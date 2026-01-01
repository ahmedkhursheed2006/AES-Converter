import './ControlPanel.css';

/**
 * ControlPanel Component
 * 
 * Provides controls for:
 * - Switching between encryption and decryption modes
 * - Toggling round details view
 * - Clearing all inputs and outputs
 */
function ControlPanel({ mode, onModeSwitch, showRoundDetails, onToggleRoundDetails, onClear }) {
    return (
        <div className="control-panel glass-effect">
            <div className="control-group">
                {/* Mode Switch */}
                <button
                    className={`mode-button ${mode === 'encrypt' ? 'active' : ''}`}
                    onClick={onModeSwitch}
                >
                    <span className="mode-text">Encrypt</span>
                </button>

                <button
                    className={`mode-button ${mode === 'decrypt' ? 'active' : ''}`}
                    onClick={onModeSwitch}
                >
                    <span className="mode-text">Decrypt</span>
                </button>
            </div>

            <div className="control-group">
                {/* Round Details Toggle */}
                <button
                    className={`toggle-button ${showRoundDetails ? 'active' : ''}`}
                    onClick={onToggleRoundDetails}
                >
                    <span className="toggle-text">
                        {showRoundDetails ? 'Hide' : 'Show'} Round Details
                    </span>
                </button>

                {/* Clear Button */}
                <button
                    className="clear-button"
                    onClick={onClear}
                >
                    <span className="clear-text">Clear All</span>
                </button>
            </div>
        </div>
    );
}

export default ControlPanel;
