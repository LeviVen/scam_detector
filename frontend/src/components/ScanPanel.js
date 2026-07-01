import React, { useState } from "react";
import "./ScanPanel.css";

// Input form for the message text, optional sender email/phone, and the "no prior history" checkbox
// Validates the phone locally and calls onScan with the collected data
export default function ScanPanel({ onScan, onClear, loading }) {
  const [text, setText] = useState("");
  const [noHistory, setNoHistory] = useState(false);
  const [senderEmail, setSenderEmail] = useState("");
  const [senderPhone, setSenderPhone] = useState("");

  // Phone format check. Prevents the request from reaching the backend with an unusable number
  function validatePhone(number) {
    if (!number.trim()) return null;
    const digits = number.replace(/[\s\-().+]/g, "");
    const withPlus = number.trim().startsWith("+") ? number.trim() : "+" + number.trim();
    if (!/^\+[1-9]\d{0,3}/.test(withPlus) || digits.length < 7 || digits.length > 15) {
      return "Invalid phone number — include country code (e.g. +1, +44, +972)";
    }
    return null;
  }

  const phoneError = senderPhone ? validatePhone(senderPhone) : null;

  function handleSubmit() {
    if (text.trim().length > 4 && !phoneError) onScan(text.trim(), noHistory, senderEmail.trim(), senderPhone.trim());
  }

  function handleClear() {
    setText("");
    setNoHistory(false);
    setSenderEmail("");
    setSenderPhone("");
    onClear();
  }

  return (
    <div className="scan-panel">
      <div className="scan-panel__header">
        <span className="scan-label">PASTE SUSPICIOUS MESSAGE</span>
        <span className="scan-counter">{text.length} chars</span>
      </div>
      <textarea
        className="scan-textarea"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={"Paste a suspicious SMS, email, WhatsApp message,\nor any text containing links here..."}
        rows={7}
        disabled={loading}
      />
      <div className="sender-fields">
        <div className="sender-field">
          <label className="sender-field__label">SENDER EMAIL <span className="optional">optional</span></label>
          <input
            className="sender-field__input"
            type="email"
            placeholder="e.g. noreply@suspicious-domain.com"
            value={senderEmail}
            onChange={(e) => setSenderEmail(e.target.value)}
            disabled={loading}
          />
        </div>
        <div className="sender-field">
          <label className="sender-field__label">SENDER PHONE <span className="optional">optional</span></label>
          <input
            className={`sender-field__input ${phoneError ? "sender-field__input--error" : ""}`}
            type="text"
            placeholder="e.g. +1-800-555-0000"
            value={senderPhone}
            onChange={(e) => setSenderPhone(e.target.value)}
            disabled={loading}
          />
          {phoneError && <span className="sender-field__error">{phoneError}</span>}
        </div>
      </div>
      <div className="history-toggle" onClick={() => !loading && setNoHistory(!noHistory)}>
        <div className={`history-checkbox ${noHistory ? "history-checkbox--checked" : ""}`}>
          {noHistory && <span className="history-checkmark">✓</span>}
        </div>
        <div className="history-label-group">
          <span className="history-label">First message — no prior conversation history</span>
          <span className="history-sublabel">
            {noHistory
              ? "Context active: AI will treat this as a cold first contact"
              : "Check this if you've never received a message from this sender before"}
          </span>
        </div>
      </div>
      <div className="scan-actions">
        <button
          className="scan-btn"
          onClick={handleSubmit}
          disabled={loading || text.trim().length < 5 || !!phoneError}
        >
          {loading ? "Analyzing..." : "Scan Message"}
        </button>
        {loading && <span className="spinner" />}
        {(text.length > 0 || senderEmail.length > 0 || senderPhone.length > 0) && !loading && (
          <button className="clear-btn" onClick={handleClear}>Clear</button>
        )}
      </div>
    </div>
  );
}