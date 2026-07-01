import React, { useState } from "react";
import "./ResultPanel.css";

// Renders one sender identity card. Handles the "unavailable" state (when the API couldn't be reached) separately from the normal flags/rows display.
function SenderCard({ label, icon, data, flags, summary, penalty }) {
  if (!data) return null;
  if (data.unavailable) return (
    <div className="sender-card sender-card--unknown">
      <div className="sender-card__header">
        <span className="sender-card__icon">{icon}</span>
        <span className="sender-card__label">{label}</span>
        <span className="sender-card__status sender-card--unknown">UNAVAILABLE</span>
      </div>
      <p className="sender-card__summary">{summary}</p>
    </div>
  );
  const hasFlags = flags && flags.length > 0;
  const cardClass = hasFlags ? (penalty >= 30 ? "sender-card--danger" : "sender-card--warn") : "sender-card--safe";

  return (
    <div className={`sender-card ${cardClass}`}>
      <div className="sender-card__header">
        <span className="sender-card__icon">{icon}</span>
        <span className="sender-card__label">{label}</span>
        <span className={`sender-card__status ${cardClass}`}>
          {hasFlags ? (penalty >= 30 ? "HIGH RISK" : "SUSPICIOUS") : "LEGITIMATE"}
        </span>
      </div>
      <p className="sender-card__summary">{summary}</p>
      {hasFlags && (
        <ul className="sender-card__flags">
          {flags.map((f, i) => (
            <li key={i} className="sender-card__flag">▸ {f}</li>
          ))}
        </ul>
      )}
      <div className="sender-card__rows">
        {data.ipqs && (
          <>
            {data.ipqs.deliverability !== undefined && (
              <div className="sender-card__row"><span>Deliverability</span><span>{data.ipqs.deliverability}</span></div>
            )}
            {data.ipqs.disposable !== undefined && (
              <div className="sender-card__row"><span>Disposable</span><span>{data.ipqs.disposable ? "Yes ⚠" : "No"}</span></div>
            )}
            {data.ipqs.freeEmail !== undefined && (
              <div className="sender-card__row"><span>Free provider</span><span>{data.ipqs.freeEmail ? "Yes" : "No"}</span></div>
            )}
            {data.ipqs.country && (
              <div className="sender-card__row"><span>Country</span><span>{data.ipqs.country}</span></div>
            )}
            {data.ipqs.fraudScore !== undefined && (
              <div className="sender-card__row">
                <span>IPQS fraud score</span>
                <span style={{ color: data.ipqs.fraudScore >= 85 ? "#aa1111" : data.ipqs.fraudScore >= 60 ? "#8a5a00" : "inherit" }}>
                  {data.ipqs.fraudScore}/100
                </span>
              </div>
            )}
            {data.ipqs.domainAge && (
              <div className="sender-card__row"><span>Domain age</span><span>{data.ipqs.domainAge}</span></div>
            )}
          </>
        )}
        {data.veriphone && (
          <>
            <div className="sender-card__row"><span>Valid</span><span>{data.veriphone.valid ? "Yes" : "No ⚠"}</span></div>
            {data.veriphone.phoneType && (
              <div className="sender-card__row"><span>Line type</span><span>{data.veriphone.phoneType}</span></div>
            )}
            {data.veriphone.carrier && (
              <div className="sender-card__row"><span>Carrier</span><span>{data.veriphone.carrier}</span></div>
            )}
            {data.veriphone.country && (
              <div className="sender-card__row"><span>Country</span><span>{data.veriphone.country}</span></div>
            )}
            {data.veriphone.internationalFormat && (
              <div className="sender-card__row"><span>Format</span><span>{data.veriphone.internationalFormat}</span></div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// Displays the full scan result: verdict badge, numeric score, plain-language summary, red flags list, sender identity cards, URL scan results with VT stats and heuristic flags, and collapsible technical details.
export default function ResultPanel({ result }) {
  const { finalScore, verdict, summary, flags, details, meta, recommendNoContact } = result;
  const verdictColor = verdict === "SAFE" ? "safe" : verdict === "SUSPICIOUS" ? "warn" : "danger";
  const verdictLabel = verdict === "SAFE" ? "Relatively Safe" : verdict === "SUSPICIOUS" ? "Suspicious" : "Dangerous";
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className={`result-panel result-panel--${verdictColor}`}>
      <div className="result-top">
        <div className="verdict-block">
          <div className={`verdict-badge verdict-badge--${verdictColor}`}>{verdictLabel}</div>
          <p className="result-summary">{summary}</p>
        </div>
        <div className={`score-box score-box--${verdictColor}`}>
          <span className="score-box__number">{finalScore}</span>
          <span className="score-box__label">/ 100</span>
        </div>
      </div>

      {flags && flags.length > 0 && (
        <div className="flags-section">
          <span className="section-label">Red Flags Detected</span>
          <ul className="flags-list">
            {flags.map((f, i) => (
              <li key={i} className="flag-item"><span className="flag-dot">▸</span>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {(details?.email || details?.phone) && (
        <div className="sender-section">
          <span className="section-label">Sender Identity Analysis</span>
          {details.sender?.emailVerdict && details.sender.emailVerdict !== "LEGITIMATE" && (
            <div className={`identity-verdict identity-verdict--${details.sender.emailVerdict.toLowerCase()}`}>
              <strong>Email verdict: {details.sender.emailVerdict}</strong> — Based on API analysis: {(details.sender.emailFlags || []).join("; ") || "no specific flags"}
            </div>
          )}
          {details.sender?.emailContext && details.sender.emailContext.verdict !== "CONSISTENT" && (
            <div className={`identity-verdict identity-verdict--${details.sender.emailContext.verdict === "INCONSISTENT" ? "dangerous" : "suspicious"}`}>
              <strong>Email context: {details.sender.emailContext.verdict}</strong> — {details.sender.emailContext.reasoning}
            </div>
          )}
          {details.sender?.phoneVerdict && details.sender.phoneVerdict !== "LEGITIMATE" && (
            <div className={`identity-verdict identity-verdict--${details.sender.phoneVerdict.toLowerCase()}`}>
              <strong>Phone verdict: {details.sender.phoneVerdict}</strong> — {(details.sender.phoneFlags || []).join("; ") || "no specific flags"}
            </div>
          )}
          {details.sender?.phoneContext && details.sender.phoneContext.verdict !== "CONSISTENT" && (
            <div className="identity-verdict identity-verdict--suspicious">
              <strong>Phone context: {details.sender.phoneContext.verdict}</strong> — {details.sender.phoneContext.reasoning}
            </div>
          )}
          {recommendNoContact && (
            <div className="no-contact-inline">
              ⚠ This sender shows suspicious signals. Even if the message seems friendly, we advise against engaging further.
            </div>
          )}
          <div className="sender-cards">
            {details.email && (
              <SenderCard label={details.email.email} icon="✉" data={details.email} flags={details.email.flags} summary={details.email.summary} penalty={details.email.penalty} />
            )}
            {details.phone && (
              <SenderCard label={details.phone.phone} icon="✆" data={details.phone} flags={details.phone.flags} summary={details.phone.summary} penalty={details.phone.penalty} />
            )}
          </div>
        </div>
      )}

      {details?.urls && details.urls.length > 0 && (
        <div className="urls-section">
          <span className="section-label">URL Scan Results</span>
          <div className="url-list">
            {details.urls.map((u, i) => {
              const itemClass = u.unresolvable ? "unresolvable"
                : u.threatLevel === "NONE" ? "safe"
                : u.threatLevel === "SUSPICIOUS_ONLY" ? "warn"
                : u.threatLevel === "MEDIUM" ? "warn"
                : u.threatLevel === "UNKNOWN" ? "unknown"
                : "danger";
              return (
                <div key={i} className={`url-item url-item--${itemClass}`}>
                  <div className="url-row">
                    <span className={`url-threat-badge url-threat-badge--${itemClass}`}>
                      {u.unresolvable ? "UNREACHABLE"
                        : u.threatLevel === "SUSPICIOUS_ONLY" ? "SUSPICIOUS"
                        : u.threatLevel === "MEDIUM" ? "MEDIUM RISK"
                        : u.threatLevel === "HIGH" ? "HIGH RISK"
                        : u.threatLevel}
                    </span>
                    <span className="url-text">{u.expanded.length > 60 ? u.expanded.slice(0, 60) + "…" : u.expanded}</span>
                  </div>
                  {u.wasRedirected && <span className="url-redirect-note">↳ redirected from {u.url}</span>}
                  {u.unresolvable && <span className="url-unresolvable-note">⚠ This URL could not be reached. The domain may be offline or taken down after sending phishing messages.</span>}
                  {u.error && !u.unresolvable && <span className="url-error">{u.error}</span>}
                  {u.vtStatus === "failed" && !u.unresolvable && <span className="url-vt-failed">VirusTotal scan failed — heuristic analysis used</span>}
                  {u.vtStatus === "success" && u.enginesRun > 0 && (
                    <span className="url-vt-stats">VirusTotal: {u.malicious} malicious · {u.suspicious} suspicious · {u.undetected} clean / {u.enginesRun} engines</span>
                  )}
                  {u.heuristicFlags && u.heuristicFlags.length > 0 && (
                    <ul className="url-heuristic-flags">
                      {u.heuristicFlags.map((f, fi) => <li key={fi}>▸ {f}</li>)}
                    </ul>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="result-footer">
        <button className="detail-toggle" onClick={() => setShowDetails(!showDetails)}>
          {showDetails ? "▴ Hide Details" : "▾ Show Details"}
        </button>
      </div>

      {showDetails && (
        <div className="detail-block">
          <div className="detail-row"><span className="detail-key">Message verdict</span><span className="detail-val">{details.message.verdict} (score: {details.message.score})</span></div>
          {details.sender?.verdict && <div className="detail-row"><span className="detail-key">Sender verdict</span><span className="detail-val">{details.sender.verdict}</span></div>}
          {details.senderPenalty > 0 && <div className="detail-row"><span className="detail-key">Sender penalty</span><span className="detail-val">-{details.senderPenalty} pts</span></div>}
          <div className="detail-row"><span className="detail-key">URL penalty</span><span className="detail-val">-{details.urlPenalty} pts</span></div>
          <div className="detail-row"><span className="detail-key">No history context</span><span className="detail-val">{meta.noHistory ? "Yes" : "No"}</span></div>
          <div className="detail-row"><span className="detail-key">URLs found</span><span className="detail-val">{meta.urlsFound}</span></div>
          <div className="detail-row"><span className="detail-key">Scanned at</span><span className="detail-val">{new Date(meta.scannedAt).toLocaleTimeString()}</span></div>
        </div>
      )}
    </div>
  );
}