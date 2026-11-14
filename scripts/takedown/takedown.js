const CONFIG = {
  SENDERS: ['soc@phishlabs.com'],
  GITHUB_OWNER: 'cunnie',
  GITHUB_REPO: 'sslip.io-blocklist',
};

function processTakedownNotices() {
  const fromQuery = CONFIG.SENDERS.map((s) => `from:${s}`).join(' OR ');
  const query = `(${fromQuery}) is:unread`;
  const threads = GmailApp.search(query, 0, 10);

  for (const thread of threads) {
    const messages = thread.getMessages();
    const latestMsg = messages[messages.length - 1];
    const subject = latestMsg.getSubject();
    const from = latestMsg.getFrom();
    const body = latestMsg.getPlainBody();

    try {
      const extracted = extractDetailsWithGemini(subject, body);

      if (!extracted || !isValidIp(extracted.ip) || !extracted.target) {
        console.warn(`Could not confidently extract data for thread: ${subject}`);
        continue;
      }

      triggerGitHubTakedown(extracted.ip, extracted.target, subject, from);

      thread.markRead();
    } catch (err) {
      console.error(`Failed processing "${subject}": ${err.message}`);
    }
  }
}

function isValidIp(ip) {
  const ipv4 = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv4.test(ip) || (ip.includes(':') && ipv6.test(ip));
}

function extractDetailsWithGemini(subject, emailBody) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent`;

  const prompt = `Extract the offending IP address and the exact "Client/Brand Targeted" value from this PhishLabs takedown notice.

Rules:
1. "target": Extract the exact string from "Client/Brand Targeted:" (e.g., "JPMorgan Chase / Chase.com"). Do not shorten or alter it unless that line is missing.
2. "ip": Extract the IP address from "Associated IP Addresses:" (or embedded in the nip.io/sslip.io URL if missing). Normalize to standard IPv4 or IPv6 format.

Subject: ${subject}

Body:
${emailBody}`;

  const payload = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: {
        type: 'OBJECT',
        properties: {
          ip: {
            type: 'STRING',
            description: 'The offending IPv4 or IPv6 address (e.g., 143.246.222.130).',
          },
          target: {
            type: 'STRING',
            description: 'Exact Client/Brand Targeted string (e.g., JPMorgan Chase / Chase.com).',
          },
        },
        required: ['ip', 'target'],
      },
    },
  };

  const response = UrlFetchApp.fetch(url, {
    method: 'post',
    headers: { 'x-goog-api-key': apiKey },
    contentType: 'application/json',
    payload: JSON.stringify(payload),
  });

  const result = JSON.parse(response.getContentText());
  const jsonText = result.candidates?.[0]?.content?.parts?.[0]?.text;
  return jsonText ? JSON.parse(jsonText) : null;
}

function triggerGitHubTakedown(ip, target, subject, from) {
  const token = PropertiesService.getScriptProperties().getProperty('GITHUB_TOKEN');
  const url = `https://api.github.com/repos/${CONFIG.GITHUB_OWNER}/${CONFIG.GITHUB_REPO}/dispatches`;

  const payload = {
    event_type: 'takedown',
    client_payload: {
      ip: ip.trim(),
      target: target.trim(),
      subject: subject.trim(),
      from: from.trim(),
    },
  };

  const response = UrlFetchApp.fetch(url, {
    method: 'post',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    contentType: 'application/json',
    payload: JSON.stringify(payload),
  });

  if (response.getResponseCode() !== 204) {
    throw new Error(`GitHub dispatch failed (${response.getResponseCode()}): ${response.getContentText()}`);
  }
}