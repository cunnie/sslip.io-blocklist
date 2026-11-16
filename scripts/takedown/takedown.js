const CONFIG = {
  // Each source finds unread notices from one sender and extracts
  // { ips: [...], target }.
  SOURCES: [
    {
      name: 'PhishLabs',
      query: 'from:soc@phishlabs.com is:unread',
      extract: (msg) => {
        const result = extractDetailsWithGemini(msg.getSubject(), msg.getPlainBody());
        return result && { ips: [result.ip], target: result.target };
      },
    },
    {
      name: 'Netcraft',
      query: 'from:netcraft.com filename:xarf.json is:unread',
      extract: (msg, messages) => extractDetailsFromXarf(messages),
    },
    {
      name: 'NCSC',
      query: 'from:reports@ncsc.nl is:unread',
      extract: (msg) => extractDetailsFromNcsc(msg.getPlainBody()),
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
        const ips = (extracted?.ips || []).filter(Boolean).map((ip) => ip.trim());
        const validIps = ips.filter(isValidIp);

        if (validIps.length < ips.length) {
          const invalid = ips.filter((ip) => !isValidIp(ip));
          console.warn(`${source.name}: ignoring invalid IP(s) ${invalid.join(', ')} in thread: ${subject}`);
        }
        if (validIps.length === 0 || !extracted.target) {
          console.warn(`${source.name}: could not confidently extract data for thread: ${subject}`);
          continue;
        }

        // One dispatch per email, with the IPs space-separated, so a burst of
        // IPs can't be lost to the workflow's one-pending-run concurrency limit.
        triggerGitHubTakedown(validIps.join(' '), extracted.target, subject, from);

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

  return { ips: [ip], target };
}

// NCSC reports list affected hosts in a CSV between two lines of #####...
// The source.ip column (normally the 2nd) holds IPv4 addresses with
// underscores instead of dots, e.g. 201_34_147_209.
function extractDetailsFromNcsc(body) {
  const blocks = body.split(/^\s*#{10,}\s*$/m);
  const ips = new Set();

  // Text between demarcation lines sits at the odd indexes.
  for (let i = 1; i < blocks.length; i += 2) {
    const lines = blocks[i].split(/\r?\n/).filter((line) => line.trim());
    if (lines.length === 0) continue;

    const header = parseCsvLine(lines[0]);
    let ipColumn = header.indexOf('source.ip');
    if (ipColumn === -1) ipColumn = 1;

    for (const line of lines.slice(1)) {
      const field = parseCsvLine(line)[ipColumn];
      if (field) ips.add(field.trim().replace(/_/g, '.'));
    }
  }

  return { ips: [...ips], target: 'Dutch HTTP vulnerability' };
}

// Splits one CSV line, allowing quoted fields that contain commas or "".
function parseCsvLine(line) {
  const fields = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"' && line[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      fields.push(field);
      field = '';
    } else {
      field += c;
    }
  }
  fields.push(field.trim());
  return fields;
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