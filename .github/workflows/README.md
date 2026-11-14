# Workflows

## `takedown.yaml`: update the blocklist from a takedown notice

Triggered by a `repository_dispatch` event with `event_type: takedown`, which
the [takedown notice processor](../../scripts/takedown/README.md) sends. The
workflow:

1. Checks that `client_payload.ip` looks like an IPv4 or IPv6 address.
2. Exits without changing anything if the IP address is already in
   `blocklist.txt`.
3. Appends `<ip> # <target>` and sorts every line after the 17-line header.
4. Commits as "Abuse Bot" using the email subject as the commit message, then
   pushes to `main`.

### Expected payload

```json
{
  "event_type": "takedown",
  "client_payload": {
    "ip": "192.0.2.1",
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
