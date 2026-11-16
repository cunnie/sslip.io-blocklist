# Takedown notice processor (Google Apps Script)

`takedown.js` runs in Google Apps Script with access to the abuse mailbox. It
finds unread takedown notices from PhishLabs, Netcraft and the Dutch NCSC,
pulls out the offending IP addresses and target brand, and sends a `repository_dispatch`
event to GitHub Actions [takedown workflow](../../.github/workflows/README.md) then
adds the IP address to `blocklist.txt`.

## How it works

1. Searches Gmail once per source in `CONFIG.SOURCES`, up to 10 threads each:
   - **PhishLabs:** `from:soc@phishlabs.com is:unread`. Sends the latest
     message's subject and body to Gemini to extract `ip` and `target`.
   - **Netcraft:** `from:netcraft.com filename:xarf.json is:unread`. Parses the
     attached `xarf.json`: `ip` is `Report.SourceIp`, and `target` is
     `OnBehalfOf.ComplainantOrg` + " " + `OnBehalfOf.ComplainantOrgDomain`
     (for example `Apple Support Scams www.apple.com`). No Gemini call.
   - **NCSC:** `from:reports@ncsc.nl is:unread`. Reads the CSV between the
     `#####################################` lines and takes every IP address
     in the `source.ip` column (normally the 2nd), changing underscores to dots
     (`201_34_147_209` → `201.34.147.209`) and dropping duplicates. `target` is
     always `Dutch HTTP vulnerability`. IPv4 only. No Gemini call.
2. Uses the latest message's subject and sender as `subject` and `from`.
3. POSTs to `https://api.github.com/repos/cunnie/sslip.io-blocklist/dispatches`
   with `event_type: takedown` and a `client_payload` of `ip`, `target`,
   `subject` and `from`. An email with several IP addresses (NCSC) sends one
   dispatch with them space-separated in `ip`, so none are lost to the
   workflow's concurrency limit.
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

**Don't deploy it.** **Deploy** is only for scripts called from outside. Instead, **Run** it.

## Secrets

Add these under **Project Settings** (gear icon) → **Script Properties**. Never
put them in the source code.

| Property         | What it is                                                                                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GITHUB_TOKEN`   | A GitHub fine-grained personal access token limited to `cunnie/sslip.io-blocklist`, with **Contents: Read and write**. A classic token needs the `repo` scope. |
| `GEMINI_API_KEY` | A Gemini API key from <https://aistudio.google.com/apikey>. Use whatever property name your `extractDetailsWithGemini` reads.                                  |

Create the GitHub token at <https://github.com/settings/personal-access-tokens>.
