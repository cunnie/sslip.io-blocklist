# Takedown notice processor (Google Apps Script)

`takedown.js` runs in Google Apps Script with access to the abuse mailbox. It
finds unread takedown notices from PhishLabs, uses Gemini to pull
out the offending IP address and target brand, and sends a `repository_dispatch`
event to GitHub. The [takedown workflow](../../.github/workflows/README.md) then
adds the IP address to `blocklist.txt`.

## How it works

1. Searches Gmail for `(from:soc@phishlabs.com) is:unread`
2. For each thread, sends the latest message's subject and body to Gemini to
   extract `ip` and `target`.
3. POSTs to `https://api.github.com/repos/cunnie/sslip.io-blocklist/dispatches`
   with `event_type: takedown` and a `client_payload` of `ip`, `target`,
   `subject` and `from`.
4. When GitHub returns 204, marks the thread read. Threads that fail extraction
   or dispatch stay unread and are retried on the next run.

Because "unread" means "not yet processed", **don't open these notices in Gmail
before the script has run**, or mark them unread again if you do.

## Setup

1. Create an Apps Script project at <https://script.google.com> while signed in
   as the account that receives the notices.
2. Paste `takedown.js` into the project (for example as `Code.gs`),
3. Add a trigger: **Triggers** (clock icon) → **Add Trigger** → function
   `processTakedownNotices`, event source **Time-driven**, for example every
   15 minutes.
4. Run `processTakedownNotices` once by hand to approve the Gmail and external
   request permissions.

## Secrets

Add these under **Project Settings** (gear icon) → **Script Properties**. Never
put them in the source code.

| Property         | What it is                                                                                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GITHUB_TOKEN`   | A GitHub fine-grained personal access token limited to `cunnie/sslip.io-blocklist`, with **Contents: Read and write**. A classic token needs the `repo` scope. |
| `GEMINI_API_KEY` | A Gemini API key from <https://aistudio.google.com/apikey>. Use whatever property name your `extractDetailsWithGemini` reads.                                  |

Create the GitHub token at <https://github.com/settings/personal-access-tokens>.
Fine-grained tokens expire, so put a reminder in your calendar to renew it.
When it expires, dispatches fail with a 401 that you can see in the Apps Script
**Executions** log.