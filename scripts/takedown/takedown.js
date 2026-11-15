const CONFIG = {
  // Each source finds unread notices from one sender and extracts { ip, target }.
  SOURCES: [
    {
      name: 'PhishLabs',
      query: 'from:soc@phishlabs.com is:unread',
      extract: (msg) => extractDetailsWithGemini(msg.getSubject(), msg.getPlainBody()),
    },
    {
      name: 'Netcraft',
      query: 'from:netcraft.com filename:xarf.json is:unread',
      extract: (msg, messages) => extractDetailsFromXarf(messages),
    },
  ],
  GITHUB_OWNER: 'cunnie',
  GITHUB_REPO: 'sslip.io-blocklist',
};

function processTakedownNotices() {
  for (const source of CONFIG.SOURCES) {
    const threads = GmailApp.search(source.query, 0, 10);

    for (const thread of threads) {
      const messages = thread.getMessages();
      const latestMsg = messages[messages.length - 1];
      const subject = latestMsg.getSubject();
      const from = latestMsg.getFrom();

      try {
        const extracted = source.extract(latestMsg, messages);

        if (!extracted || !isValidIp(extracted.ip) || !extracted.target) {
          console.warn(`${source.name}: could not confidently extract data for thread: ${subject}`);
          continue;
        }

        triggerGitHubTakedown(extracted.ip, extracted.target, subject, from);

        thread.markRead();
      } catch (err) {
        console.error(`${source.name}: failed processing "${subject}": ${err.message}`);
      }
    }
  }
}

// Netcraft attaches an X-ARF report (xarf.json) to each takedown notice.
// Use the newest message in the thread that has one, in case a later reply
// in the same thread has no attachment.
function extractDetailsFromXarf(messages) {
  const attachment = messages
    .slice()
    .reverse()
    .flatMap((m) => m.getAttachments())
    .find((a) => /xarf\.json$/i.test(a.getName()));
  if (!attachment) {
    return null;
  }

  const xarf = JSON.parse(attachment.getDataAsString());
  const ip = xarf.Report?.SourceIp;
  const org = xarf.OnBehalfOf?.ComplainantOrg;
  const domain = xarf.OnBehalfOf?.ComplainantOrgDomain;
  const target = [org, domain].filter(Boolean).join(' ');

  return { ip, target };
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