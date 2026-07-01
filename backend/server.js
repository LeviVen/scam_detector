require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const https = require("follow-redirects").https;
const http = require("follow-redirects").http;
const { URL } = require("url");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const IPQS_API_KEY = process.env.IPQS_API_KEY;
const VERIPHONE_API_KEY = process.env.VERIPHONE_API_KEY;

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "online",
  "site", "web", "info", "biz", "live", "shop", "store", "club", "vip",
  "win", "loan", "work", "download", "stream"
]);

const SUSPICIOUS_KEYWORDS = [
  "secure-login", "verify", "account-suspended", "update-info", "confirm-identity",
  "banking", "paypal", "amazon", "apple", "microsoft", "google", "netflix",
  "login", "signin", "password", "credential", "auth", "wallet", "reward",
  "prize", "claim", "winner", "free", "alert", "suspended", "limited"
];


// Extracts all URLs found in the message text using a regex
// Returns a set so repeated links are only checked once
function extractUrls(text) {
  const urlRegex = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)/gi;
  return [...new Set(text.match(urlRegex) || [])];
}

// Removes all URLs from the message text before it is sent to the LLM, so the AI judges only the language/manipulation tactics, not links.
function stripUrls(text) {
  return text.replace(/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)/gi, "").trim();
}


// Scores a single URL locally
// Checks for suspicious TLD, phishing keywords, brand impersonation,
// raw IP address, HTTP (non-HTTPS), excessive subdomains, randomly-generated
// subdomains, and hosting on free/shared platforms
function heuristicUrlScore(urlString) {
  const flags = [];
  let penalty = 0;
  try {
    const parsed = new URL(urlString);
    const host = parsed.hostname.replace("www.", "");
    const tld = host.split(".").pop().toLowerCase();
    const path = (parsed.pathname + parsed.search).toLowerCase();
    const fullUrl = urlString.toLowerCase();

    if (SUSPICIOUS_TLDS.has(tld)) { penalty += 30; flags.push(`Suspicious TLD: .${tld}`); }

    const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(k => fullUrl.includes(k));
    if (matchedKeywords.length > 0) {
      penalty += Math.min(matchedKeywords.length * 10, 30);
      flags.push(`Suspicious keywords in URL: ${matchedKeywords.join(", ")}`);
    }

    const domainParts = host.split(".");
    if (domainParts.length > 3) { penalty += 15; flags.push("Excessive subdomains (common in phishing)"); }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(parsed.hostname)) { penalty += 35; flags.push("URL uses raw IP address instead of domain"); }

    if (parsed.protocol === "http:") { penalty += 10; flags.push("Non-HTTPS connection"); }

    const brandNames = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "bank", "ebay"];
    const isBrandInPath = brandNames.some(b => path.includes(b));
    const isBrandInDomain = brandNames.some(b => host.includes(b));
    const knownBrandDomains = ["paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com", "netflix.com"];
    const isLegitDomain = knownBrandDomains.some(d => host === d || host.endsWith("." + d));

    if ((isBrandInPath || isBrandInDomain) && !isLegitDomain) {
      penalty += 25;
      flags.push("Brand name used in suspicious domain/path (possible impersonation)");
    }

    const subdomain = domainParts.length > 2 ? domainParts[0] : null;
    if (subdomain) {
      const randomSubdomainRegex = /^[a-z0-9]{8,}$|([a-z]{2,4}\d{3,}|\d{3,}[a-z]{2,4}|[a-z0-9]{4,}-[a-z0-9]{4,}-[a-z0-9]{4,})/i;
      const hasHighEntropy = subdomain.length > 8 && (subdomain.match(/\d/g) || []).length >= 3 && (subdomain.match(/[a-z]/g) || []).length >= 3;
      if (randomSubdomainRegex.test(subdomain) || hasHighEntropy) {
        penalty += 20;
        flags.push(`Randomly-generated subdomain detected: ${subdomain} (common in phishing hosting)`);
      }
    }

    const suspiciousHostingPatterns = ["appmedo", "myshopify", "webflow", "netlify", "vercel", "glitch", "repl.co", "ngrok", "trycloudflare"];
    const isFreePlatform = suspiciousHostingPatterns.some(p => host.includes(p));
    if (isFreePlatform && (isBrandInPath || matchedKeywords.length > 0)) {
      penalty += 15;
      flags.push("Phishing content hosted on a free/shared platform");
    }
  } catch {
    penalty += 20;
    flags.push("Malformed URL");
  }
  return { penalty, flags };
}

// Follows HTTP redirects (up to 15 HEAD requests) to reveal the true final destination of a URL, since scam links often hide behind shorteners
function expandUrl(url) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(url);
      const lib = parsed.protocol === "https:" ? https : http;
      const req = lib.request(
        { method: "HEAD", host: parsed.hostname, path: parsed.pathname + parsed.search, maxRedirects: 15 },
        (res) => resolve(res.responseUrl || url)
      );
      req.on("error", (err) => reject(err));
      req.setTimeout(6000, () => { req.destroy(); reject(new Error("timeout")); });
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

// Runs expandUrl on every URL in parallel. If a URL cannot be resolved (because the domain is offline/blocked), it is marked unresolvable, which is treated as a suspicious signal later on.
async function expandAllUrls(urls) {
  return Promise.all(
    urls.map(async (url) => {
      try {
        const expanded = await expandUrl(url);
        const wasRedirected = expanded !== url;
        return { original: url, expanded, wasRedirected, unresolvable: false };
      } catch {
        return { original: url, expanded: url, wasRedirected: false, unresolvable: true };
      }
    })
  );
}

// Calls the IPQS API to collect email reputation red flags (disposable, deliverability, fraud score, recent abuse, honeypot, breach/leak data, MX records). Each flag adds to the penalty.
async function checkEmail(email) {
  if (!email || !email.trim()) return null;
  const result = { email, ipqs: null, flags: [], penalty: 0, summary: "" };

  try {
    const res = await axios.get(
      `https://ipqualityscore.com/api/json/email/${IPQS_API_KEY}/${encodeURIComponent(email)}`,
      { timeout: 8000 }
    );
    const d = res.data;
    result.ipqs = {
      valid: d.valid,
      deliverability: d.deliverability,
      fraudScore: d.fraud_score,
      disposable: d.disposable,
      freeEmail: d.free_email,
      spam: d.spam,
      suspicious: d.suspicious,
      recentAbuse: d.recent_abuse,
      honeypot: d.honeypot,
      leaked: d.leaked,
      mxFound: d.mx_found,
      smtpScore: d.smtp_score,
      domainAge: d.domain_age?.human,
      country: d.country,
    };

    if (d.disposable) { result.flags.push("Disposable/temporary email address detected"); result.penalty += 35; }
    if (!d.valid) { result.flags.push("Email address format is invalid"); result.penalty += 20; }
    if (d.deliverability === "low") { result.flags.push("Email is likely undeliverable"); result.penalty += 20; }
    if (!d.mx_found) { result.flags.push("No MX records — domain cannot receive email"); result.penalty += 25; }
    if (d.fraud_score >= 85) { result.flags.push(`IPQS fraud score very high: ${d.fraud_score}/100`); result.penalty += 30; }
    else if (d.fraud_score >= 60) { result.flags.push(`IPQS fraud score elevated: ${d.fraud_score}/100`); result.penalty += 15; }
    if (d.recent_abuse) { result.flags.push("Email reported for recent abuse or spam"); result.penalty += 25; }
    if (d.honeypot) { result.flags.push("Email is a known honeypot/spam trap"); result.penalty += 30; }
    if (d.leaked) { result.flags.push("Email found in data breach records"); result.penalty += 10; }

    result.penalty = Math.min(result.penalty, 60);
    result.summary = result.flags.length > 0
      ? `Sender email raised ${result.flags.length} concern(s): ${result.flags[0]}${result.flags.length > 1 ? ` and ${result.flags.length - 1} more` : ""}.`
      : "Sender email appears legitimate.";

    return result;
  } catch (err) {
    console.error("[EMAIL] check failed:", err.message);
    result.summary = "Email validation unavailable.";
    return result;
  }
}

// Calls the Veriphone API to validate phone number structure and collect line type (VOIP/mobile/toll-free/premium), carrier and country. Each flag adds to the penalty
async function checkPhone(phone) {
  if (!phone || !phone.trim()) return null;
  let cleanPhone = phone.trim().replace(/[\s\-().]/g, "");
  if (!cleanPhone.startsWith("+")) cleanPhone = "+" + cleanPhone;

  const result = { phone, veriphone: null, flags: [], penalty: 0, summary: "" };

  try {
    const res = await axios.get(
      `https://api.veriphone.io/v2/verify?phone=${encodeURIComponent(cleanPhone)}`,
      { headers: { Authorization: `Bearer ${VERIPHONE_API_KEY}` }, timeout: 8000 }
    );
    const d = res.data;

    result.veriphone = {
      valid: d.phone_valid,
      phoneType: d.phone_type,
      carrier: d.carrier || null,
      country: d.country || null,
      countryCode: d.country_code || null,
      nationalFormat: d.phone_national || null,
      internationalFormat: d.phone_international || null,
    };

    if (d.phone_valid === false) { result.flags.push("Phone number is invalid or does not exist"); result.penalty += 20; }
    if (d.phone_type === "voip") { result.flags.push("VOIP number — commonly used by scammers to mask identity"); result.penalty += 25; }
    if (d.phone_type === "toll_free") { result.flags.push("Toll-free number — unusual for personal messages"); result.penalty += 10; }
    if (d.phone_type === "premium_rate") { result.flags.push("Premium rate number — calls/messages may incur charges"); result.penalty += 20; }

    result.penalty = Math.min(result.penalty, 60);
    result.summary = result.flags.length > 0
      ? `Sender phone raised ${result.flags.length} concern(s): ${result.flags[0]}${result.flags.length > 1 ? ` and ${result.flags.length - 1} more` : ""}.`
      : "Sender phone appears legitimate.";

    return result;
  } catch (err) {
    console.error("[PHONE] Veriphone check failed:", err.message);
    result.summary = "Phone validation unavailable.";
    result.unavailable = true;
    return result;
  }
}

// Separate LLM call that receives both the phone API data AND the message text. Checks for language/country mismatch and whether a toll-free number makes sense for the content.
async function analyzePhoneContextWithGroq(messageBody, phoneResult) {
  if (!phoneResult?.veriphone) return null;
  const { country, carrier, phoneType, valid } = phoneResult.veriphone;
  if (!country && phoneType !== "toll_free") return null;

  const prompt = `You are a cybersecurity expert evaluating whether a phone number's metadata is consistent with the message content.

Phone number data:
- Country: ${country || "unknown"}
- Carrier: ${carrier || "unknown"}
- Line type: ${phoneType || "unknown"}
- Valid number: ${valid}

Message to analyze:
"""
${messageBody.slice(0, 500)}
"""

Your job is to detect two specific issues:

1. COUNTRY/LANGUAGE MISMATCH: Detect the language the message is written in. Then check if it is plausible that someone from ${country || "an unknown country"} would send a message in that language. For example, a message in Hebrew from a Chinese number is suspicious. A message in English from a US number is normal. A message in Hebrew from an Israeli number is normal. Consider that expats and international users exist, so be reasonable — only flag clear mismatches.

2. TOLL-FREE CONTEXT: If the line type is "toll_free", assess whether using a toll-free number makes sense for this message. Toll-free numbers are normal for businesses but suspicious for personal messages (e.g. "hey it's Tim, I got a new phone").

Return ONLY a valid JSON object with no markdown, no code fences:
{
  "contextScore": <integer 0-100 where 0=very suspicious context, 100=fully consistent>,
  "contextVerdict": "<one of: CONSISTENT, SUSPICIOUS, INCONSISTENT>",
  "contextReasoning": "<1-2 sentences explaining the assessment>",
  "contextFlags": ["<specific issues found, empty array if none>"]
}`;

  try {
    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      { model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.1, response_format: { type: "json_object" } },
      { headers: { Authorization: `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000 }
    );
    return JSON.parse(response.data.choices[0].message.content.trim());
  } catch { return null; }
}

// LLM prompt that receives only the stripped message body and scores manipulation tactics: urgency, authority claims, prize offers,
// and requests for personal info. The noHistory flag adds context that a signals a first massage from this sender.
async function analyzeMessageWithGroq(messageBody, noHistory) {
  const stripped = stripUrls(messageBody);

  if (!stripped || stripped.replace(/\s/g, "").length < 3) {
    return {
      score: noHistory ? 40 : 50,
      verdict: "SUSPICIOUS",
      reasoning: "Message contained only a URL with no accompanying text." + (noHistory ? " No prior message history adds suspicion." : ""),
      flags: noHistory ? ["No prior message history with this sender"] : []
    };
  }

  const historyContext = noHistory
    ? `IMPORTANT CONTEXT: This is the FIRST and ONLY message from this sender — no prior conversation history.
- A bank sending urgent warnings cold is highly suspicious.
- A stranger offering prizes or requiring immediate action with no prior relationship is a strong scam indicator.
- A simple greeting with no links or requests is normal and should not be penalized heavily.`
    : `CONTEXT: There IS prior message history with this sender. Reduce (but don't eliminate) suspicion for messages that might otherwise seem out of place.`;

  const prompt = `You are a cybersecurity expert analyzing message text for phishing and scam patterns.
You will receive ONLY the message body text, with all URLs already removed.
Do not comment on links or URLs — analyze only the text for manipulation tactics.

${historyContext}

Return ONLY a valid JSON object with no markdown, no code fences, no extra text.

The JSON must have exactly these fields:
{
  "score": <integer 0-100 where 0=definitely scam, 100=definitely safe>,
  "verdict": "<one of: SAFE, SUSPICIOUS, DANGEROUS>",
  "reasoning": "<2-3 sentence explanation based only on the message text>",
  "flags": ["<list of detected red flags in the text, empty array if none>"]
}

Red flags to check: urgency/pressure language, requests for personal/financial info, threats of account suspension, prizes/lottery claims, impersonation of authorities, grammar issues suggesting automated text, requests to act immediately, cold first contact claiming authority or offering rewards.

Message body to analyze (URLs removed):
"""
${stripped}
"""`;

  const response = await axios.post(
    "https://api.groq.com/openai/v1/chat/completions",
    { model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.1, response_format: { type: "json_object" } },
    { headers: { Authorization: `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000 }
  );
  return JSON.parse(response.data.choices[0].message.content.trim());
}

// Converts the accumulated email API penalty into a classification
function emailVerdictFromApi(emailResult) {
  if (!emailResult || !emailResult.ipqs) return { verdict: null, flags: [], penalty: 0 };
  const p = emailResult.penalty || 0;
  const flags = emailResult.flags || [];
  let verdict;
  if (p >= 45) verdict = "DANGEROUS";
  else if (p >= 20) verdict = "SUSPICIOUS";
  else verdict = "LEGITIMATE";
  return { verdict, flags, penalty: p };
}

// Separate LLM call that receives both the email API data AND the message text. Checks for identity mismatch and whether fraud signals in the email are consistent with what the message is asking for.
async function analyzeEmailContextWithGroq(messageBody, emailResult) {
  if (!emailResult?.ipqs) return null;
  const d = emailResult.ipqs;

  const dataLines = [
    `Email address: ${emailResult.email}`,
    `Valid format: ${d.valid}`,
    `Deliverability: ${d.deliverability}`,
    `Disposable/temporary address: ${d.disposable}`,
    `Free email provider (Gmail/Yahoo/etc): ${d.freeEmail}`,
    `MX records found: ${d.mxFound}`,
    `IPQS fraud score: ${d.fraudScore}/100`,
    `Recent abuse reported: ${d.recentAbuse}`,
    `Known honeypot/spam trap: ${d.honeypot}`,
    `Found in data breaches: ${d.leaked}`,
    `Country: ${d.country || "unknown"}`,
  ];
  if (d.domainAge) dataLines.push(`Domain age: ${d.domainAge}`);

  const prompt = `You are a cybersecurity expert evaluating whether a sender's email address is consistent with the message they sent.

Email validation data:
${dataLines.join("\n")}

Message to analyze:
"""
${messageBody.slice(0, 500)}
"""

Your job is to detect two specific issues:

1. IDENTITY MISMATCH: Does the email address match what the message claims? For example:
   - A message claiming to be from PayPal, a bank, or a government body but sent from a Gmail, disposable, or free email provider is highly suspicious.
   - A message claiming to be from a friend or colleague sent from Gmail is completely normal.
   - A message with no identity claim is neutral — just assess the email quality.
   - A very new domain sending urgent security warnings is suspicious.

2. SENDER RISK IN CONTEXT: Given the message content, how risky is this sender?
   - A high fraud score combined with a message requesting personal details is very dangerous.
   - A disposable email combined with urgency language is a strong scam indicator.
   - Free email providers alone are NOT suspicious — only flag if combined with identity claims or other red flags.

Return ONLY a valid JSON object with no markdown, no code fences:
{
  "contextScore": <integer 0-100 where 0=very suspicious in context, 100=fully consistent>,
  "contextVerdict": "<one of: CONSISTENT, SUSPICIOUS, INCONSISTENT>",
  "contextReasoning": "<1-2 sentences explaining the assessment>",
  "contextFlags": ["<specific issues found combining email data and message content, empty array if none>"]
}`;

  try {
    const response = await axios.post(
      "https://api.groq.com/openai/v1/chat/completions",
      { model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.1, response_format: { type: "json_object" } },
      { headers: { Authorization: `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000 }
    );
    return JSON.parse(response.data.choices[0].message.content.trim());
  } catch { return null; }
}

// First do a heurstic check and if the URL is unresolvable skip VirusTotal, else send the URL to VT and poll the result with retries (it takes a while for the engines to report), then combine the result with the heuristic score
async function checkUrlWithVirusTotal(urlData) {
  const heuristic = heuristicUrlScore(urlData.expanded);

  if (urlData.unresolvable) {
    return {
        url: urlData.original, expanded: urlData.expanded, wasRedirected: false, unresolvable: true,
        malicious: 0, suspicious: 0, total: 0, safe: false, threatLevel: "UNRESOLVABLE",
        heuristicPenalty: heuristic.penalty, heuristicFlags: heuristic.flags, vtStatus: "skipped",
        error: "URL could not be reached — domain may be offline, blocked, or non-existent",
    };
  }

  try {
      const submitRes = await axios.post(
        "https://www.virustotal.com/api/v3/urls",
        `url=${encodeURIComponent(urlData.expanded)}`,
        { headers: { "x-apikey": VIRUSTOTAL_API_KEY, "Content-Type": "application/x-www-form-urlencoded" }, timeout: 10000 }
      );

      const analysisId = submitRes.data.data.id;
      let stats = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        await new Promise((r) => setTimeout(r, 5000));
        const reportRes = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": VIRUSTOTAL_API_KEY }, timeout: 10000,
        });
        const status = reportRes.data.data.attributes.status;
        stats = reportRes.data.data.attributes.stats;
        if (status === "completed") break;
        console.log(`[VT] analysis not ready (attempt ${attempt + 1}), retrying...`);
      }

      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const undetected = stats.undetected || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      const enginesRun = total - (stats.timeout || 0);

      let vtThreatLevel;
      if (malicious >= 2) vtThreatLevel = "HIGH";
      else if (malicious === 1) vtThreatLevel = "MEDIUM";
      else if (suspicious >= 1) vtThreatLevel = "SUSPICIOUS_ONLY";
      else vtThreatLevel = "NONE";

      let heuristicThreatLevel = heuristic.penalty >= 40 ? "HIGH" : heuristic.penalty >= 20 ? "MEDIUM" : "NONE";
      const threatLevelOrder = ["NONE", "SUSPICIOUS_ONLY", "MEDIUM", "HIGH"];
      const threatLevel = threatLevelOrder[Math.max(threatLevelOrder.indexOf(vtThreatLevel), threatLevelOrder.indexOf(heuristicThreatLevel))];

      const result = {
        url: urlData.original, expanded: urlData.expanded, wasRedirected: urlData.wasRedirected,
        unresolvable: false, malicious, suspicious, undetected, enginesRun, total,
        safe: threatLevel === "NONE", threatLevel, heuristicPenalty: heuristic.penalty,
        heuristicFlags: heuristic.flags, vtStatus: "success",
      };

      return result;
    } catch {
      const heuristicThreatLevel = heuristic.penalty >= 40 ? "HIGH" : heuristic.penalty >= 20 ? "MEDIUM" : "NONE";
      return {
        url: urlData.original, expanded: urlData.expanded, wasRedirected: urlData.wasRedirected,
        unresolvable: false, malicious: 0, suspicious: 0, total: 0, safe: heuristicThreatLevel === "NONE",
        threatLevel: heuristicThreatLevel, heuristicPenalty: heuristic.penalty,
        heuristicFlags: heuristic.flags, vtStatus: "failed",
        error: "VirusTotal scan failed — heuristic analysis used instead",
      };
  }
}

const VT_PENALTIES = { HIGH: 65, MEDIUM: 35, SUSPICIOUS_ONLY: 32, NONE: 0, UNRESOLVABLE: 32 };
const VT_LABELS = {
  HIGH: "Confirmed malicious URL (2+ security engines flagged)",
  MEDIUM: "Likely malicious URL (1 engine flagged)",
  SUSPICIOUS_ONLY: "URL flagged as suspicious by security vendors",
  UNRESOLVABLE: "Unresolvable domain — may be taken down after sending phishing messages",
};

// Converts the accumulated phone API penalty into a classification (>=45 DANGEROUS, 20-44 SUSPICIOUS, <20 LEGITIMATE)
function phoneVerdictFromApi(phoneResult) {
  if (!phoneResult || (!phoneResult.veriphone && !phoneResult.ipqs)) return { verdict: null, flags: [], penalty: 0 };
  if (phoneResult.unavailable) return { verdict: null, flags: [], penalty: 0 };
  const p = phoneResult.penalty || 0;
  const flags = phoneResult.flags || [];
  let verdict;
  if (p >= 45) verdict = "DANGEROUS";
  else if (p >= 20) verdict = "SUSPICIOUS";
  else verdict = "LEGITIMATE";
  return { verdict, flags, penalty: p };
}

// Combines everything into one final score: finalScore = LLM message score - URL penalties - sender penalty (>=70 SAFE, 40-69 SUSPICIOUS, <40 DANGEROUS). 
// Sender result can change the base verdict when SUSPICIOUS or INCONSISTENT context is found (because if the sender is suspicious, the message might be okay but future messages might be dangerous).
function aggregateScore(msgResult, emailResult, emailContextResult, phoneResult, phoneContextResult, urlResults) {
  let msgScore = msgResult.score;
  let urlPenalty = 0;
  let urlFlags = [];

  for (const url of urlResults) {
    const vtPenalty = VT_PENALTIES[url.threatLevel] || 0;
    const hPenalty = url.heuristicPenalty || 0;
    let combinedPenalty = Math.min(vtPenalty + hPenalty, 65);
    if (url.unresolvable) { combinedPenalty = Math.max(combinedPenalty, VT_PENALTIES.UNRESOLVABLE); urlFlags.push(`URL is unreachable and could not be scanned: ${url.url}`); }
    if (url.wasRedirected) { combinedPenalty += 10; urlFlags.push(`URL redirects to a different destination: ${url.url} → ${url.expanded}`); }
    if (url.vtStatus === "failed" && !url.unresolvable) { combinedPenalty = Math.max(combinedPenalty, 10); urlFlags.push(`VirusTotal scan failed for: ${url.expanded}`); }
    if (combinedPenalty > 0) {
      urlPenalty += combinedPenalty;
      if (VT_LABELS[url.threatLevel]) urlFlags.push(VT_LABELS[url.threatLevel]);
      if (url.heuristicFlags && url.heuristicFlags.length > 0) urlFlags.push(...url.heuristicFlags);
    }
  }

  const msgFinalScore = Math.max(0, Math.min(100, msgScore - urlPenalty));

  const senderScore = null;
  const recommendNoContact = false;

  const emailApi = emailVerdictFromApi(emailResult);
  let emailVerdict = emailApi.verdict;

  let emailContextPenalty = 0;
  let emailContextFlags = [];
  if (emailContextResult) {
    if (emailContextResult.contextVerdict === "INCONSISTENT") { emailContextPenalty = 32; }
    else if (emailContextResult.contextVerdict === "SUSPICIOUS") { emailContextPenalty = 15; }
    emailContextFlags = emailContextResult.contextFlags || [];
    if (emailContextPenalty > 0 && emailVerdict === "LEGITIMATE") emailVerdict = "SUSPICIOUS";
    if (emailContextPenalty >= 32 && emailVerdict !== "DANGEROUS") emailVerdict = "DANGEROUS";
  }

  const phoneApi = phoneVerdictFromApi(phoneResult);
  let phoneVerdict = phoneApi.verdict;

  let phoneContextPenalty = 0;
  let phoneContextFlags = [];
  if (phoneContextResult) {
    if (phoneContextResult.contextVerdict === "INCONSISTENT") { phoneContextPenalty = 32; }
    else if (phoneContextResult.contextVerdict === "SUSPICIOUS") { phoneContextPenalty = 15; }
    phoneContextFlags = phoneContextResult.contextFlags || [];
    if (phoneContextPenalty > 0 && phoneVerdict === "LEGITIMATE") phoneVerdict = "SUSPICIOUS";
    if (phoneContextPenalty >= 32 && phoneVerdict !== "DANGEROUS") phoneVerdict = "DANGEROUS";
  }

  const senderVerdict = emailVerdict === "DANGEROUS" || phoneVerdict === "DANGEROUS" ? "DANGEROUS"
    : emailVerdict === "SUSPICIOUS" || phoneVerdict === "SUSPICIOUS" ? "SUSPICIOUS"
    : (emailVerdict === "LEGITIMATE" || phoneVerdict === "LEGITIMATE") ? "LEGITIMATE"
    : null;

  let senderPenalty = 0;
  if (senderVerdict === "DANGEROUS") senderPenalty = 65;
  else if (senderVerdict === "SUSPICIOUS") senderPenalty = 35;

  const finalScore = Math.max(0, Math.min(100, msgFinalScore - senderPenalty));

  let verdict;
  if (finalScore >= 70) verdict = "SAFE";
  else if (finalScore >= 40) verdict = "SUSPICIOUS";
  else verdict = "DANGEROUS";

  const allFlags = [...new Set([...(msgResult.flags || []), ...urlFlags, ...emailApi.flags, ...emailContextFlags, ...phoneApi.flags, ...phoneContextFlags])];

  const senderWarning = senderVerdict === "DANGEROUS"
    ? " The sender has been flagged as malicious — do not engage with this sender under any circumstances."
    : senderVerdict === "SUSPICIOUS"
    ? " The sender's identity raised concerns — exercise caution."
    : "";

  let summary;
  if (verdict === "DANGEROUS") {
    const senderDriven = senderVerdict === "DANGEROUS" && msgFinalScore >= 40;
    if (senderDriven) {
      const emailCtxReason = emailContextResult?.contextReasoning || "";
      summary = `This sender has been flagged as malicious. ${emailCtxReason} Even if the message seems harmless, engaging with this sender is high risk.${senderWarning}`;
    } else {
      summary = `This message is likely a scam or phishing attempt. ${msgResult.reasoning}${urlFlags.length ? " Dangerous or suspicious URLs were detected." : ""}${senderWarning}`;
    }
  } else if (verdict === "SUSPICIOUS") {
    const upgradedBySender = msgFinalScore >= 70 && senderVerdict !== "LEGITIMATE";
    if (upgradedBySender) {
      const emailCtxReason = emailContextResult?.contextReasoning || "";
      summary = `The message itself appears safe, but the sender's identity is suspicious. ${emailCtxReason} Scammers often send friendly messages at first to build trust before requesting personal details.${senderWarning}`;
    } else {
      summary = `Proceed with caution. ${msgResult.reasoning}${urlFlags.length ? " URL analysis also raised concerns." : ""}${senderWarning}`;
    }
  } else {
    summary = `This message appears safe. ${msgResult.reasoning}`;
  }

  return { finalScore, verdict, summary, allFlags, msgScore, urlPenalty, senderPenalty, senderVerdict, emailVerdict, phoneVerdict, recommendNoContact };
}

// Main scan endpoint. Runs few parallel processes in two phases
// Phase 1 - URL expansion + email check + phone check run in parallel
// Phase 2 - message LLM + email context LLM + phone context LLM run in parallel
// after that VirusTotal scans the URL, and finally aggregateScore combines everything into the response that is sent back to the client.
app.post("/api/scan", async (req, res) => {
  const { text, noHistory, senderEmail, senderPhone } = req.body;
  if (!text || text.trim().length < 5) {
    return res.status(400).json({ error: "Please provide a message to scan." });
  }

  if (senderPhone) {
    const digits = senderPhone.replace(/[\s\-().+]/g, "");
    const withPlus = senderPhone.trim().startsWith("+") ? senderPhone.trim() : "+" + senderPhone.trim();
    const countryCodeRegex = /^\+[1-9]\d{0,3}/;
    if (!countryCodeRegex.test(withPlus) || digits.length < 7 || digits.length > 15) {
      return res.status(400).json({ error: "Invalid phone number. Please include the country code (e.g. +1, +44, +972) and ensure the number is between 7 and 15 digits." });
    }
  }

  const rawUrls = extractUrls(text);
  const senderValue = senderEmail || senderPhone || null;
  const senderType = senderEmail ? "email" : senderPhone ? "phone" : null;

  try {
    const [expandedUrls, emailResult, phoneResult] = await Promise.all([
      rawUrls.length > 0 ? expandAllUrls(rawUrls) : Promise.resolve([]),
      senderEmail ? checkEmail(senderEmail) : Promise.resolve(null),
      senderPhone ? checkPhone(senderPhone) : Promise.resolve(null),
    ]);

    const emailHasData = emailResult?.ipqs !== null && emailResult?.ipqs !== undefined;
    const phoneHasData = phoneResult?.veriphone !== null && phoneResult?.veriphone !== undefined;

    const [msgResult, emailContextResult, phoneContextResult] = await Promise.all([
      analyzeMessageWithGroq(text, !!noHistory),
      (emailResult && emailHasData) ? analyzeEmailContextWithGroq(text, emailResult) : Promise.resolve(null),
      (phoneResult && phoneHasData) ? analyzePhoneContextWithGroq(text, phoneResult) : Promise.resolve(null),
    ]);

    const urlResults = [];
    for (let i = 0; i < expandedUrls.length; i++) {
      const result = await checkUrlWithVirusTotal(expandedUrls[i]);
      urlResults.push(result);
      if (i < expandedUrls.length - 1) await new Promise((r) => setTimeout(r, 16000));
    }

    const aggregated = aggregateScore(msgResult, emailResult, emailContextResult, phoneResult, phoneContextResult, urlResults);

    res.json({
      finalScore: aggregated.finalScore,
      verdict: aggregated.verdict,
      summary: aggregated.summary,
      flags: aggregated.allFlags,
      recommendNoContact: aggregated.recommendNoContact,
      details: {
        message: { score: aggregated.msgScore, reasoning: msgResult.reasoning, verdict: msgResult.verdict },
        sender: {
          verdict: aggregated.senderVerdict,
          emailVerdict: aggregated.emailVerdict,
          phoneVerdict: aggregated.phoneVerdict,
          emailFlags: emailResult?.flags ?? [],
          phoneFlags: phoneResult?.flags ?? [],
          emailContext: emailContextResult ? {
            verdict: emailContextResult.contextVerdict,
            reasoning: emailContextResult.contextReasoning,
            flags: emailContextResult.contextFlags,
          } : null,
          phoneContext: phoneContextResult ? {
            verdict: phoneContextResult.contextVerdict,
            reasoning: phoneContextResult.contextReasoning,
            flags: phoneContextResult.contextFlags,
          } : null,
        },
        urls: urlResults,
        urlPenalty: aggregated.urlPenalty,
        senderPenalty: aggregated.senderPenalty,
        senderScore: aggregated.senderScore,
        email: emailResult,
        phone: phoneResult,
      },
      meta: { urlsFound: rawUrls.length, noHistory: !!noHistory, hasSenderEmail: !!senderEmail, hasSenderPhone: !!senderPhone, scannedAt: new Date().toISOString() },
    });
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ error: "Scan failed. Check your API keys and try again.", details: err.message });
  }
});

app.listen(PORT, () => console.log(`Scam Detector backend running on port ${PORT}`));