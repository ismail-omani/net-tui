# net-tui

English | [Русский](README.ru.md)

A TUI tool for auditing your local network: it discovers devices, scans their services, and
checks whether they still accept factory-default credentials.

> ⚠️ **Only scan networks you own.** Run this tool exclusively on a network you own or have
> written permission to test. Attempting to log in to devices you do not own may be illegal.

## Features

- host discovery via `arp-scan --localnet` (fallback: `nmap -sn`);
- port and service scanning via `nmap -sS/-sT -sV` (+ OS detection when running as root);
- vendor detection from the OUI, nmap product data, and `http-title`;
- default-credential testing with vendor-specific pairs tried first;
- protocols: **HTTP/HTTPS** (Basic, Digest, HTML-form heuristic), **SSH**, **Telnet**, **FTP**,
  **RTSP**, **SNMP v1/v2c**, **VNC**, **MQTT**, **IPP**;
- Bubble Tea TUI: device table, live log, progress, pause, details, rescan;
- headless mode and `--dry-run`;
- results are written to disk immediately and survive Ctrl+C.

## Requirements

- Linux;
- Go 1.26+ to build (tested on 1.27);
- `nmap`;
- `arp-scan` and `sudo` are optional, but they improve discovery quality and vendor detection;
- internet access is only needed for `--fetch-creds` (afterwards everything works offline).

## Build

```bash
go build -o net-tui ./cmd/net-tui
# or
make build
```

## Quick start

```bash
# 1. Download the default-credential lists into data/creds/
./net-tui --fetch-creds

# 2. Start the TUI
./net-tui

# Headless: discovery + nmap only, no login attempts
./net-tui --no-tui --yes --dry-run --target 192.168.1.0/24

# Headless full audit
./net-tui --no-tui --yes --target 192.168.1.0/24
```

When started without `--target`, the tool inspects `ip -j a`, discards loopback and inactive
interfaces, and picks the active subnet. If several active subnets are available, the TUI asks
you to choose one.

`arp-scan` and `nmap -O` require root. The TUI asks for the sudo password inside the interface and
keeps it in memory only. If sudo is unavailable or you press `Esc`, the tool continues
unprivileged: `nmap -sn` + `-sT -sV` (no MAC/OUI vendor and no OS detection). If your system
forbids passing the sudo password over stdin (`requiretty`), run the whole application as root:
`sudo ./net-tui`.

## TUI controls

| Key | Action |
|---|---|
| `↑`/`↓`, `j`/`k` | select a device |
| `Enter` | device details / back to the log |
| `p` | pause/resume credential probing |
| `s` | rescan (after completion) |
| `e` | open the results directory (`xdg-open`) |
| `PgUp`/`PgDn` | scroll the log |
| `q`, `Ctrl+C` | quit (findings already written are kept) |

When the scan finishes, the TUI shows the final state, closes itself after about 2 seconds
(`q` closes immediately), and prints a final line such as
`+ scan done: 3 devices, 0 findings, 42s` plus the results path. This makes it clear that the
run completed rather than hanging.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--fetch-creds` | | download/refresh credential lists and exit |
| `--no-tui` | `false` | headless mode |
| `--dry-run` | `false` | discovery + nmap, no login attempts |
| `--target CIDR` | auto | scan the specified private subnet |
| `--iface NAME` | auto | force a network interface |
| `--ports LIST` | built-in list | ports for nmap |
| `--concurrency N` | `8` | global probe concurrency |
| `--max-creds N` | `20` | maximum credentials per host/protocol |
| `--timeout DUR` | `6s` | per-probe timeout |
| `--attempt-delay DUR` | `300ms` | delay between login attempts |
| `--results DIR` | `results` | results directory |
| `--creds DIR` | `data/creds` | credential-list directory |
| `--yes` | `false` | skip the authorization prompt (headless) |
| `--verbose` | `false` | log every probe error |
| `--version` | | print the version |

Built-in port list:
`21,22,23,80,443,554,631,1883,2222,2323,5000,5900-5902,7547,8000,8080,8081,8088,8443,8554,8883,9000,37777,34567,49152`
plus UDP `161` for SNMP.

## Output

For every IP with at least one working default login, `results/<ip>.json` is created:

```json
[
  {
    "protocol": "http",
    "port": 80,
    "vendor": "TP-Link",
    "login": "admin",
    "password": "admin"
  },
  {
    "protocol": "telnet",
    "port": 23,
    "vendor": "TP-Link",
    "login": "admin",
    "password": "admin"
  }
]
```

Additional files:

- `results/_devices.json` — inventory: MAC, vendor, hostname, all open ports/services, findings, notes;
- `results/_attempts.jsonl` — audit trail of every attempt (JSON Lines, **plaintext passwords**).

Final statuses in `_devices.json`: `found` (findings exist), `clean` (ports checked, no findings),
`no ports` (no open ports found), `scanned` (`--dry-run`).

Both `_devices.json` and every `_attempts.jsonl` line contain a `run` field (for example,
`20261107-155812`) identifying the run. `_attempts.jsonl` is appended across runs, so `run` makes
it easy to see which attempts belong to the current scan.

Empty `<ip>.json` files are not created. Writes are atomic (tmp + rename). A rescan merges into
existing files (exact duplicates are not added).

## How it works

1. Detect interfaces and subnets (`ip -j addr show`).
2. `arp-scan --interface <if> --localnet` → IP, MAC, OUI vendor.
   If arp-scan is unavailable or returns nothing, fall back to `nmap -sn`.
3. Run `nmap` against the discovered IPs: open ports, service/product/version, `http-title`, OS.
4. Refine the vendor from the OUI + nmap product + title and normalize it to a canonical brand.
   Values such as `(Unknown: locally administered)` are ignored, so, for example, AmpliFi is
   identified as Ubiquiti from its `http-title` instead of staying "unknown".
5. Build a credential plan for each service: vendor-specific pairs (up to ~2/3 of the limit), then
   the generic top list (`admin/admin`, `root/root`, …), without duplicates.
6. Probes run in parallel: 8 global workers, at most 2 concurrent attempts per host, a 300 ms delay
   between attempts, and a protocol stops after its first success.
7. A finding is written to `results/<ip>.json` and the audit log immediately.

### Success criteria

- **HTTP Basic/Digest** — the server returned `401` and, after credentials were supplied, returned
  a non-`401` response;
- **HTTP form** — at least 2 signals are required: a new cookie, a redirect to another page, the
  password form disappearing, or success words such as `dashboard`/`logout`/`welcome`; failure
  words such as `invalid`/`incorrect`/`failed` must be absent. A single signal is treated as
  uncertain and is **not** recorded. ZTE F680/ONT-style pages with inputs outside a `<form>` are
  supported: the password is posted as `SHA256(password + UserRandomNum)` together with
  `Frm_Loginchecktoken`, and failure messages inside inline scripts are detected as well;
- **SSH** — successful `x/crypto/ssh` authentication (password or keyboard-interactive);
- **Telnet** — a `login:`/`password:` prompt, credentials sent, and a shell prompt or welcome
  message, with no login errors (including IAC negotiation handling);
- **FTP** — `230` after `USER`/`PASS`;
- **RTSP** — `401` challenge, then `200` for `DESCRIBE` with Basic/Digest;
- **SNMP** — a successful `GET sysDescr.0` with community `public`/`private` (`login` is empty and
  the community is stored in `password`);
- **VNC** — security type `None` (open access, empty login/password) or a successful DES
  challenge-response with a default password;
- **MQTT** — `CONNACK` with code `0` (anonymous or with credentials);
- **IPP** — `Get-Printer-Attributes` returned `successful-ok` after Basic authentication.

## Credential database

`--fetch-creds` downloads into `data/creds/`:

- [SecLists default-passwords.csv](https://github.com/danielmiessler/SecLists) (Vendor, Username, Password);
- [ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet);
- [routersploit defaults.txt](https://github.com/threat9/routersploit).

Entries are indexed by brand (`tp-link`, `hikvision`, `dahua`, `mikrotik`, …); unknown vendors use
the generic list. Lists can be updated manually — the parsing format is described in
`internal/creds/store.go`. Without network access, the tool works with the files already
downloaded.

## Limitations

- HTML forms are parsed heuristically: CAPTCHAs, JavaScript password encryption, non-standard
  field names, and two-step logins may not be supported;
- an SNMP community is not exactly a "login", but it is still a default secret;
- VNC `None`, anonymous MQTT, and SNMP communities are recorded with an empty `login`;
- scanning "all devices" includes phones and PCs — SSH/Telnet/HTTP attempts will be made against
  them as well;
- active login attempts can lock accounts or trigger IP bans on cameras and routers; for sensitive
  networks use `--max-creds 1..5` and a larger `--timeout`;
- `_attempts.jsonl` contains every attempted password in plaintext — store the `results/` directory
  accordingly;
- the tool does not exploit vulnerabilities or bypass authentication: it only checks known factory
  credentials.

## Development

```bash
go test ./...
go vet ./...
make build
```

Structure:

```
cmd/net-tui/        CLI, headless mode
internal/tui/       Bubble Tea interface
internal/engine/    phase orchestration, probe planning
internal/scan/      arp-scan and nmap (XML parsing)
internal/probe/     HTTP, SSH, Telnet, FTP, RTSP, SNMP, VNC, MQTT, IPP
internal/creds/     credential loading/indexing, vendor matching
internal/report/    results/<ip>.json, _devices.json, _attempts.jsonl
internal/priv/      root/sudo
internal/netutil/   interfaces and subnets
```
