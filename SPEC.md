# port-inspector — Design Specification

## Overview

`port-inspector` is a zero-dependency single binary that lists open network
ports on the local machine, enriched with process and Docker container
information. It is written in Go and compiles to a self-contained executable
for Linux, macOS, and Windows.

---

## Output

All results are presented in a single unified table sorted by port number
(ascending), then protocol. Columns:

| Column  | Description |
|---------|-------------|
| PORT    | Host port number |
| PROTO   | `tcp4`, `tcp6`, `udp4`, or `udp6` — derived from the bind address |
| ADDRESS | Local bind address |
| STATE   | Connection state (e.g. `LISTEN`, `ESTABLISHED`) |
| PID     | Owning process ID, or `—` if unavailable |
| PROCESS | Human-readable process name (see Process Name Resolution) |
| SOURCE  | `system` or `docker` |

Rendered using `github.com/olekukonko/tablewriter` with box-drawing borders.
ANSI colour is automatically disabled when stdout is not a TTY.

### Default filtering

The following entries are hidden by default and require a flag to show:

| Hidden by default | Flag to reveal |
|---|---|
| Non-`LISTEN` states (e.g. `ESTABLISHED`) | `--all` |
| `CLOSE` state entries | `--all` |
| Container-only ports (`(container-only)` address) | `--all` |
| IPv6 addresses | `-6` |

`--all` disables all state-based filtering but does not enable IPv6 — pass both
`--all -6` to see everything.

### JSON output

`--json` emits a flat JSON array of `PortEntry` objects to stdout instead of
the table. Useful for piping into `jq` or other tools.

---

## Data Model

```go
type PortEntry struct {
    Port          int    // host port
    Protocol      string // "tcp" or "udp"
    LocalAddress  string // bind address
    State         string // LISTEN, ESTABLISHED, CLOSE, etc.
    PID           int    // 0 = unknown
    ProcessName   string // resolved display name
    Source        string // "system" or "docker"
    ContainerName string // docker container name, if applicable
    ContainerID   string // short (12-char) container ID
    Image         string // container image name
    ContainerPort int    // container-side port (docker only)
}
```

---

## System Port Collection

Dispatches to an OS-specific backend. All backends deduplicate entries on the
`(port, protocol, pid, state)` tuple.

### Linux

Reads the following `/proc/net` virtual files directly — no external tools
required:

- `/proc/net/tcp` — IPv4 TCP
- `/proc/net/tcp6` — IPv6 TCP
- `/proc/net/udp` — IPv4 UDP
- `/proc/net/udp6` — IPv6 UDP

Each file row contains a hex-encoded local address (`host:port`), a TCP state
code, and a socket inode number.

**Address decoding** (`hexToIPPort`): the address field is a little-endian
hex-encoded 32-bit (IPv4) or 128-bit (IPv6) integer. For IPv4 the 8-char hex
value is reversed byte-by-byte. For IPv6 four consecutive 32-bit words are each
reversed.

**PID resolution** (`inodeToPID`): walks every `/proc/<pid>/fd/*` symlink
looking for one that resolves to `socket:[<inode>]`. This is dependency-free
but O(processes × fds); requires read access to `/proc/<pid>/fd` (typically
needs root for processes owned by other users).

**TCP state mapping**: hex state codes (`0A` = LISTEN, `01` = ESTABLISHED,
etc.) are decoded to string names.

### macOS / FreeBSD

Runs `netstat -anv` (with `-p tcp` when listen-only mode is active). Output
lines are parsed field-by-field. Local address uses dot-separated
`host.port` notation; the port field may be a service name which is resolved
via `net.LookupPort`.

### Windows

Runs `netstat -ano`. PID is the last column. Process name is looked up via
`tasklist /FI "PID eq <pid>" /FO CSV /NH`. The `LISTENING` state is normalised
to `LISTEN` for consistency.

---

## Process Name Resolution

`procName(pid)` returns a display name for a PID using OS-specific mechanisms:

| OS      | Primary source | Fallback |
|---------|---------------|---------|
| Linux   | `readlink /proc/<pid>/exe` | `/proc/<pid>/comm` |
| macOS   | `ps -p <pid> -o comm=` | — |
| Windows | `tasklist /FI "PID eq <pid>"` | — |

### Interpreter enrichment

When the executable basename matches a known interpreter, the display name is
extended with the script being run: `interpreter(label)`.

Recognised interpreters: `node`, `nodejs`, `python`, `python2`, `python3`,
`ruby`, `perl`, `php`, `bun`, `deno`, `java`, `ts-node`, `tsx`, `npx`.
Version suffixes are matched by prefix (e.g. `python3.11` matches `python3`).

**Argv scanning** (`procCmdline`): reads `/proc/<pid>/cmdline` (NUL-separated)
on Linux, runs `ps -p <pid> -o command=` on macOS, or queries WMI on Windows.
The first non-flag positional argument that contains a path separator or a
dotted basename is taken as the script path.

**Label derivation** (`scriptLabel`): converts a script path to a short label:

- If the path contains `node_modules/<pkg>/...`, the package name is returned
  (e.g. `.npm/_npx/.../node_modules/clay-server/lib/daemon.js` → `clay-server`).
- Scoped packages are preserved: `node_modules/@scope/pkg/...` → `@scope/pkg`.
- Otherwise the basename of the path is used (e.g. `server.py`).

---

## Docker Port Collection

Requires the `docker` CLI to be present in `PATH`. No Docker SDK dependency.

1. `docker ps -q` — get IDs of all running containers.
2. `docker inspect <id> ...` — fetch full JSON for all containers in one call.
3. Parse `NetworkSettings.Ports` map, keyed by `"<containerPort>/<proto>"`.

Each binding produces one `PortEntry` with `Source = "docker"`. Ports that are
`EXPOSE`d but not published to the host (empty binding list) are recorded with
`LocalAddress = "(container-only)"`.

### docker-proxy cross-reference

`docker-proxy` processes appear on the *system* side because they are host
processes. After both system and docker entries are collected, a
`port/proto → containerName` index is built from the docker entries. Any system
entry whose `ProcessName` is `docker-proxy` is looked up in this index; if
found, its `ContainerName` is populated and its `Source` is changed to
`"docker"` so it appears consistently in the table.

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `--all` | Show all connection states; do not hide `CLOSE`, non-LISTEN, or container-only entries |
| `-6` | Include IPv6 ports (hidden by default) |
| `--json` | Output a flat JSON array instead of the table |
| `--no-docker` | Skip Docker inspection |
| `--no-system` | Skip system port inspection |
| `--sudo` | Re-invoke the binary with `sudo` for full PID resolution; all other flags are forwarded; `--sudo` itself is stripped to prevent infinite re-invocation |

---

## Build

```makefile
build:
    GOOS=linux GOARCH=amd64 go build -o port-inspector-linux .
```

The binary has no runtime dependencies. All Docker interaction goes through the
`docker` CLI subprocess; the only Go dependency is
`github.com/olekukonko/tablewriter` for table rendering.
