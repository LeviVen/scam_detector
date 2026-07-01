import React, { useState } from "react";
import "./App.css";
import ScanPanel from "./components/ScanPanel";
import ResultPanel from "./components/ResultPanel";

// Root component and state manager for the app. 
// Holds the scan result, loading and error state, and passes handlers down to ScanPanel and the result down to ResultPanel.
export default function App() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(text, noHistory, senderEmail, senderPhone) {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, noHistory, senderEmail: senderEmail || undefined, senderPhone: senderPhone || undefined }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");
      setResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="header">
        Scam & Phishing Detector
      </header>
      <main className="main">
        <ScanPanel onScan={handleScan} onClear={() => { setResult(null); setError(null); }} loading={loading} />
        {error && (
          <div className="error-box">
            <span className="error-icon">⚠</span>
            <span>{error}</span>
          </div>
        )}
        {result && <ResultPanel result={result} />}
      </main>
    </div>
  );
}