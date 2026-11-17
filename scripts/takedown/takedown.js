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
    {
      name: 'Doppel',
      query: 'from:takedowns@doppel.com is:unread',
      extract: (msg) => extractDetailsFromDoppel(msg.getPlainBody()),
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
    const rows = parseCsv(blocks[i]);
    if (rows.length === 0) continue;

    let ipColumn = rows[0].indexOf('source.ip');
    if (ipColumn === -1) ipColumn = 1;

    for (const row of rows.slice(1)) {
      const field = row[ipColumn];
      if (field) ips.add(field.trim().replace(/_/g, '.'));
    }
  }

  return { ips: [...ips], target: 'Dutch HTTP vulnerability' };
}

// Doppel notices name the site on an "Infringing Site:" line with a defanged
// URL, e.g. hxxp[://]72[.]60[.]112[.]232[.]sslip[.]io. The IP to block is
// the one embedded in that hostname. Ignore the "IP Address: Domain IP
// Address:" line: that's the address of our own nameserver/web server.
// target is the rights holder plus the "Official Site:", e.g.
// "Amazon.com, Inc amazon.co".
function extractDetailsFromDoppel(body) {
  const ips = new Set();
  for (const m of body.matchAll(/^\s*Infringing Site:\s*(\S+)/gim)) {
    const ip = ipFromSslipHostname(hostnameFromDefangedUrl(m[1]));
    if (ip) ips.add(ip);
  }

  const official = body.match(/^\s*Official Site:\s*(\S+)/im)?.[1];
  const owner = (
    body.match(/on behalf of\s+(.+?)\s*,\s*the trademark/i) ||
    body.match(/is using\s+(.+?)\s+trademark/i)
  )?.[1].replace(/\s+/g, ' ');
  const target = [owner, official].filter(Boolean).join(' ');

  return { ips: [...ips], target };
}

// hxxp[://]72[.]60[.]112[.]232[.]sslip[.]io/path → 72.60.112.232.sslip.io
function hostnameFromDefangedUrl(url) {
  const refanged = url
    .replace(/\[(\.|:\/\/|:)\]/g, '$1')
    .replace(/\(\.\)/g, '.')
    .replace(/^hxxp/i, 'http');
  return refanged
    .replace(/^[a-z]+:\/\//i, '')
    .split(/[\/?#:]/)[0]
    .toLowerCase()
    .replace(/\.$/, '');
}

// Pulls the embedded IP from an sslip.io/nip.io hostname, e.g.
// 1.2.3.4.sslip.io, www.1-2-3-4.sslip.io, foo-1.2.3.4.nip.io,
// 2001-db8--1.sslip.io. Returns null if there isn't one.
function ipFromSslipHostname(hostname) {
  const ipv4 = hostname.match(/(?:^|[.-])(\d{1,3}(?:[.-]\d{1,3}){3})\.(?:sslip|nip)\.io$/);
  if (ipv4) {
    return ipv4[1].replace(/-/g, '.');
  }
  const ipv6 = hostname.match(/(?:^|\.)([0-9a-f]*-[0-9a-f-]*)\.sslip\.io$/);
  if (ipv6) {
    const ip = ipv6[1].replace(/-/g, ':');
    if (isValidIp(ip)) return ip;
  }
  return null;
}

// Parses CSV text into rows of fields. Quoted fields may contain commas, ""
// and line breaks: NCSC's plain-text emails are wrapped at about 76
// characters, which can put a line break inside a quoted field, e.g.
// "2026-11-15<newline>20:54:34.161000". Blank lines are skipped.
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;

  const endRow = () => {
    row.push(field.trim());
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
    field = '';
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"' && text[i + 1] === '"') {
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
      row.push(field);
      field = '';
    } else if (c === '\n') {
      endRow();
    } else if (c !== '\r') {
      field += c;
    }
  }
  endRow();
  return rows;
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