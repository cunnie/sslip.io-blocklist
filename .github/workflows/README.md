# Workflows

## `takedown.yaml`: update the blocklist from a takedown notice

Triggered by a `repository_dispatch` event with `event_type: takedown`, which
the [takedown notice processor](../../scripts/takedown/README.md) sends. The
workflow:

1. Splits `client_payload.ip` on spaces. It may hold one IP address or several.
2. Skips any address that doesn't look like IPv4 or IPv6, or that is already in
   `blocklist.txt`.
3. Appends `<ip> # <target>` for each remaining address and sorts every line
   after the 17-line header.
4. Commits as "Abuse Bot" using the email subject as the commit message, with
   the sender in the body, then pushes to `main`.

If nothing is new, it exits without committing. It fails only when the payload
contains no valid IP address at all.

### Expected payload

```json
{
  "event_type": "takedown",
  "client_payload": {
    "ip": "192.0.2.1 192.0.2.2",
    "target": "Example Bank",
    "subject": "Phishing report: ...",
    "from": "soc@phishlabs.com"
  }
}
```

The workflow itself needs **no secrets**.

### Testing by hand

This makes a real commit to `blocklist.txt`, so revert it afterwards:

```sh
gh api repos/cunnie/sslip.io-blocklist/dispatches \
  -f event_type=takedown \
  -f 'client_payload[ip]=192.0.2.1' \
  -f 'client_payload[target]=Test' \
  -f 'client_payload[subject]=Test takedown dispatch' \
  -f 'client_payload[from]=test@example.com'
```
