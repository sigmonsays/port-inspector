package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

// ── Data models ───────────────────────────────────────────────────────────────

type PortEntry struct {
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	State         string `json:"state"`
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	Source        string `json:"source"` // "system" or "docker"
	ContainerName string `json:"container_name,omitempty"`
	ContainerID   string `json:"container_id,omitempty"`
	Image         string `json:"image,omitempty"`
	ContainerPort int    `json:"container_port,omitempty"`
}

// ── ANSI colours ──────────────────────────────────────────────────────────────

var useColor bool

func init() {
	fi, err := os.Stdout.Stat()
	useColor = err == nil && (fi.Mode()&os.ModeCharDevice != 0)
}

func color(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

const (
	bold    = "1"
	dim     = "2"
	cyan  = "36"
	green = "32"
)

func bc(code, s string) string { return color(bold+";"+code, s) }

// ── Process name lookup ───────────────────────────────────────────────────────

// interpreters is the set of executable base names that are script runners.
// When matched, we also append the basename of the script argument.
var interpreters = map[string]bool{
	"node":    true,
	"nodejs":  true,
	"python":  true,
	"python2": true,
	"python3": true,
	"ruby":    true,
	"perl":    true,
	"php":     true,
	"bun":     true,
	"deno":    true,
	"java":    true,
	"ts-node": true,
	"tsx":     true,
	"npx":     true,
}

// procCmdline returns the full argv for a PID.
func procCmdline(pid int) []string {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err == nil {
			return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		}
	case "darwin", "freebsd":
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
		if err == nil {
			return strings.Fields(strings.TrimSpace(string(out)))
		}
	case "windows":
		out, err := exec.Command(
			"wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid),
			"get", "CommandLine", "/value",
		).Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "CommandLine=") {
					return strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "CommandLine="))
				}
			}
		}
	}
	return nil
}

// formatProcName returns a display name for a process. For known interpreter
// executables it returns "interpreter(script)" when the script argument is a file.
func formatProcName(execPath string, pid int) string {
	base := filepath.Base(execPath)

	// Match interpreter, ignoring version suffixes (e.g. "python3.11" → "python3")
	matched := ""
	if interpreters[base] {
		matched = base
	} else {
		for k := range interpreters {
			if strings.HasPrefix(base, k) {
				matched = k
				break
			}
		}
	}
	if matched == "" {
		return base
	}

	// Walk argv looking for the first non-flag argument that looks like a file
	for _, arg := range procCmdline(pid)[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.ContainsAny(arg, "/\\") || strings.Contains(filepath.Base(arg), ".") {
			return base + "(" + scriptLabel(arg) + ")"
		}
		break
	}
	return base
}

// scriptLabel derives a human-friendly label from a script path.
// For paths containing "node_modules/<pkg>/..." it returns <pkg>.
// Otherwise it returns the basename of the path.
func scriptLabel(path string) string {
	// Normalise to forward slashes for uniform matching
	norm := filepath.ToSlash(path)
	const marker = "node_modules/"
	if idx := strings.LastIndex(norm, marker); idx != -1 {
		rest := norm[idx+len(marker):]
		// rest is "<pkg>/..." or "@scope/<pkg>/..."
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 1 {
			pkg := parts[0]
			// Scoped package: combine "@scope" + "<pkg>"
			if strings.HasPrefix(pkg, "@") && len(parts) >= 2 {
				return pkg + "/" + parts[1]
			}
			return pkg
		}
	}
	return filepath.Base(path)
}

// procName returns the display name for a given PID.
func procName(pid int) string {
	if pid == 0 {
		return "—"
	}
	switch runtime.GOOS {
	case "linux":
		// Prefer /proc/<pid>/exe — gives the real path, resolves symlinks
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			return formatProcName(exe, pid)
		}
		// Fallback: comm (kernel truncates to 15 chars, no script info)
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			return strings.TrimSpace(string(data))
		}
	case "darwin", "freebsd":
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
		if err == nil {
			return formatProcName(strings.TrimSpace(string(out)), pid)
		}
	case "windows":
		out, err := exec.Command(
			"tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH",
		).Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(out)), ",")
			if len(parts) > 0 {
				return formatProcName(strings.Trim(parts[0], `"`), pid)
			}
		}
	}
	return "unknown"
}

// ── System ports ──────────────────────────────────────────────────────────────

func getSystemPorts(listenOnly bool) ([]PortEntry, error) {
	switch runtime.GOOS {
	case "linux":
		return getSystemPortsLinux(listenOnly)
	case "darwin", "freebsd":
		return getSystemPortsDarwin(listenOnly)
	case "windows":
		return getSystemPortsWindows(listenOnly)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// ── Linux: read /proc/net/tcp*, /proc/net/udp* ───────────────────────────────

var procNetFiles = []struct {
	path  string
	proto string
}{
	{"/proc/net/tcp", "tcp"},
	{"/proc/net/tcp6", "tcp"},
	{"/proc/net/udp", "udp"},
	{"/proc/net/udp6", "udp"},
}

// hexToIPPort decodes a Linux /proc/net entry like "0100007F:0050" →
// ("127.0.0.1", 80).  Works for both IPv4 (8 hex chars) and IPv6 (32 hex chars).
func hexToIPPort(s string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("bad format: %s", s)
	}
	portVal, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	h := parts[0]
	var ip net.IP
	switch len(h) {
	case 8: // IPv4, little-endian 32-bit
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return "", 0, err
		}
		ip = net.IP{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	case 32: // IPv6, four little-endian 32-bit words
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(h[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return "", 0, err
			}
			ip[i*4+0] = byte(v)
			ip[i*4+1] = byte(v >> 8)
			ip[i*4+2] = byte(v >> 16)
			ip[i*4+3] = byte(v >> 24)
		}
	default:
		return "", 0, fmt.Errorf("unexpected addr length: %d", len(h))
	}
	return ip.String(), int(portVal), nil
}

// tcpState maps Linux /proc/net/tcp state codes to human-readable strings.
var tcpState = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING",
}

func parseProcNetFile(path, proto string, listenOnly bool) ([]PortEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // file may not exist (e.g. no IPv6)
	}
	defer f.Close()

	var entries []PortEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localRaw := fields[1]
		stateHex := strings.ToUpper(fields[3])
		inodeStr := fields[9]

		state := tcpState[stateHex]
		if state == "" {
			state = stateHex
		}

		if listenOnly && proto == "tcp" && state != "LISTEN" {
			continue
		}

		ip, port, err := hexToIPPort(localRaw)
		if err != nil {
			continue
		}

		inode, _ := strconv.ParseUint(inodeStr, 10, 64)
		pid := inodeToPID(inode)
		name := procName(pid)

		entries = append(entries, PortEntry{
			Port:         port,
			Protocol:     proto,
			LocalAddress: ip,
			State:        state,
			PID:          pid,
			ProcessName:  name,
			Source:       "system",
		})
	}
	return entries, scanner.Err()
}

// inodeToPID scans /proc/*/fd/* symlinks to find which process owns a socket
// inode.  Expensive but dependency-free.
func inodeToPID(inode uint64) int {
	if inode == 0 {
		return 0
	}
	target := fmt.Sprintf("socket:[%d]", inode)

	procDir, err := os.Open("/proc")
	if err != nil {
		return 0
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err == nil && link == target {
				return pid
			}
		}
	}
	return 0
}

func getSystemPortsLinux(listenOnly bool) ([]PortEntry, error) {
	var all []PortEntry
	seen := map[string]bool{}

	for _, pf := range procNetFiles {
		entries, err := parseProcNetFile(pf.path, pf.proto, listenOnly)
		if err != nil {
			continue // missing file is fine
		}
		for _, e := range entries {
			key := fmt.Sprintf("%d-%s-%d-%s", e.Port, e.Protocol, e.PID, e.State)
			if !seen[key] {
				seen[key] = true
				all = append(all, e)
			}
		}
	}
	return all, nil
}

// ── macOS/BSD: use netstat -anvp ──────────────────────────────────────────────

func getSystemPortsDarwin(listenOnly bool) ([]PortEntry, error) {
	args := []string{"-anvp", "tcp"}
	if !listenOnly {
		args = []string{"-anv"}
	}
	out, err := exec.Command("netstat", args...).Output()
	if err != nil {
		// try without -p (older macOS)
		out, err = exec.Command("netstat", "-anv").Output()
		if err != nil {
			return nil, fmt.Errorf("netstat failed: %w", err)
		}
	}

	var entries []PortEntry
	seen := map[string]bool{}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		proto = strings.TrimRight(proto, "46")

		localField := fields[3]
		stateField := ""
		pidField := ""

		if strings.HasPrefix(fields[0], "tcp") {
			if len(fields) >= 6 {
				stateField = fields[5]
			}
			// PID is last field on macOS netstat -v
			if len(fields) >= 9 {
				pidField = fields[len(fields)-1]
			}
		} else {
			if len(fields) >= 8 {
				pidField = fields[len(fields)-1]
			}
		}

		if listenOnly && proto == "tcp" && stateField != "LISTEN" {
			continue
		}

		// parse local address  host.port or [ipv6].port
		lastDot := strings.LastIndex(localField, ".")
		if lastDot < 0 {
			continue
		}
		host := localField[:lastDot]
		portStr := localField[lastDot+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			// might be a service name
			p, err2 := net.LookupPort(proto, portStr)
			if err2 != nil {
				continue
			}
			port = p
		}

		pid, _ := strconv.Atoi(pidField)
		name := procName(pid)
		state := stateField
		if state == "" {
			state = "—"
		}

		key := fmt.Sprintf("%d-%s-%d-%s", port, proto, pid, state)
		if !seen[key] {
			seen[key] = true
			entries = append(entries, PortEntry{
				Port:         port,
				Protocol:     proto,
				LocalAddress: host,
				State:        state,
				PID:          pid,
				ProcessName:  name,
				Source:       "system",
			})
		}
	}
	return entries, nil
}

// ── Windows: use netstat -ano ─────────────────────────────────────────────────

func getSystemPortsWindows(listenOnly bool) ([]PortEntry, error) {
	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var entries []PortEntry
	seen := map[string]bool{}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		localField := fields[1]
		state := ""
		pidStr := ""

		if proto == "tcp" {
			if len(fields) >= 5 {
				state = fields[3]
				pidStr = fields[4]
			}
		} else {
			if len(fields) >= 4 {
				pidStr = fields[3]
			}
		}

		if listenOnly && proto == "tcp" && state != "LISTENING" {
			continue
		}

		lastColon := strings.LastIndex(localField, ":")
		if lastColon < 0 {
			continue
		}
		host := localField[:lastColon]
		port, err := strconv.Atoi(localField[lastColon+1:])
		if err != nil {
			continue
		}

		pid, _ := strconv.Atoi(pidStr)
		name := procName(pid)
		if state == "LISTENING" {
			state = "LISTEN"
		}
		if state == "" {
			state = "—"
		}

		key := fmt.Sprintf("%d-%s-%d-%s", port, proto, pid, state)
		if !seen[key] {
			seen[key] = true
			entries = append(entries, PortEntry{
				Port:         port,
				Protocol:     proto,
				LocalAddress: host,
				State:        state,
				PID:          pid,
				ProcessName:  name,
				Source:       "system",
			})
		}
	}
	return entries, nil
}

// ── Docker ports (via `docker inspect`) ──────────────────────────────────────

// dockerContainer is a minimal struct matching the JSON from `docker inspect`.
type dockerContainer struct {
	ID   string `json:"Id"`
	Name string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func getDockerPorts() ([]PortEntry, error) {
	// Check docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found in PATH")
	}

	// Get running container IDs
	idsOut, err := exec.Command("docker", "ps", "-q").Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}
	ids := strings.Fields(string(idsOut))
	if len(ids) == 0 {
		return nil, nil // no running containers
	}

	// Inspect all at once
	args := append([]string{"inspect"}, ids...)
	inspectOut, err := exec.Command("docker", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect failed: %w", err)
	}

	var containers []dockerContainer
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		return nil, fmt.Errorf("parsing docker inspect output: %w", err)
	}

	var entries []PortEntry
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		image := c.Config.Image

		for portProto, bindings := range c.NetworkSettings.Ports {
			parts := strings.SplitN(portProto, "/", 2)
			containerPort, _ := strconv.Atoi(parts[0])
			proto := "tcp"
			if len(parts) == 2 {
				proto = strings.ToLower(parts[1])
			}

			if len(bindings) == 0 {
				// Exposed but not published
				entries = append(entries, PortEntry{
					Port:          containerPort,
					Protocol:      proto,
					LocalAddress:  "(container-only)",
					State:         "LISTEN",
					PID:           0,
					ProcessName:   "docker",
					Source:        "docker",
					ContainerName: name,
					ContainerID:   shortID,
					Image:         image,
					ContainerPort: containerPort,
				})
				continue
			}

			for _, b := range bindings {
				hostPort, err := strconv.Atoi(b.HostPort)
				if err != nil || hostPort == 0 {
					continue
				}
				hostIP := b.HostIP
				if hostIP == "" {
					hostIP = "0.0.0.0"
				}
				entries = append(entries, PortEntry{
					Port:          hostPort,
					Protocol:      proto,
					LocalAddress:  hostIP,
					State:         "LISTEN",
					PID:           0,
					ProcessName:   "docker-proxy",
					Source:        "docker",
					ContainerName: name,
					ContainerID:   shortID,
					Image:         image,
					ContainerPort: containerPort,
				})
			}
		}
	}
	return entries, nil
}

// ── Rendering ─────────────────────────────────────────────────────────────────

// isIPv6 returns true when addr is a valid IPv6 address.
func isIPv6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// protoLabel returns "tcp4"/"udp4" or "tcp6"/"udp6" based on the bind address.
func protoLabel(proto, addr string) string {
	proto = strings.ToLower(proto)
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() == nil {
		return proto + "6"
	}
	return proto + "4"
}

var headers = []string{"PORT", "PROTO", "ADDRESS", "STATE", "PID", "PROCESS", "SOURCE"}

func renderAll(entries []PortEntry) {
	if len(entries) == 0 {
		fmt.Println(color(dim, "  (no entries)"))
		return
	}

	t := tablewriter.NewTable(os.Stdout,
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Formatting: tw.CellFormatting{
					AutoFormat: tw.On,
					Alignment:  tw.AlignCenter,
				},
			},
			Row: tw.CellConfig{
				Formatting: tw.CellFormatting{
					Alignment: tw.AlignLeft,
				},
			},
		}),
	)

	t.Header(headers)
	for _, e := range entries {
		pid := "—"
		if e.PID != 0 {
			pid = strconv.Itoa(e.PID)
		}
		process := e.ProcessName
		if e.Source == "docker" && e.ContainerName != "" {
			process = e.ContainerName
		}
		t.Append([]string{
			strconv.Itoa(e.Port),
			protoLabel(e.Protocol, e.LocalAddress),
			e.LocalAddress,
			e.State,
			pid,
			process,
			e.Source,
		})
	}
	t.Render()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	jsonOut := flag.Bool("json", false, "Output raw JSON instead of tables")
	noDocker := flag.Bool("no-docker", false, "Skip Docker inspection")
	noSystem := flag.Bool("no-system", false, "Skip system port inspection")
	showAll := flag.Bool("all", false, "Show all connections, not just LISTEN")
	show6 := flag.Bool("6", false, "Include IPv6 ports")
	useSudo := flag.Bool("sudo", false, "Re-invoke this program with sudo")
	flag.Parse()

	if *useSudo {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error resolving executable path: %v\n", err)
			os.Exit(1)
		}
		// Pass through all flags except --sudo to avoid infinite re-invocation
		var args []string
		flag.Visit(func(f *flag.Flag) {
			if f.Name != "sudo" {
				args = append(args, fmt.Sprintf("--%s=%s", f.Name, f.Value.String()))
			}
		})
		cmd := exec.Command("sudo", append([]string{exe}, args...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(cmd.ProcessState.ExitCode())
		}
		return
	}

	var systemEntries []PortEntry
	var dockerEntries []PortEntry
	var errs []string

	if !*noSystem {
		entries, err := getSystemPorts(!*showAll)
		if err != nil {
			errs = append(errs, fmt.Sprintf("system ports: %v", err))
		} else {
			systemEntries = entries
		}
	}

	if !*noDocker {
		entries, err := getDockerPorts()
		if err != nil {
			errs = append(errs, fmt.Sprintf("docker: %v", err))
		} else {
			dockerEntries = entries
		}
	}

	// Cross-reference docker-proxy system processes with docker inspect entries.
	// When a match is found, enrich the system entry with the container name and
	// drop the docker inspect entry — it is redundant (no PID, same port).
	dockerByPort := make(map[string]string) // port/proto → container name
	for _, e := range dockerEntries {
		key := fmt.Sprintf("%d/%s", e.Port, e.Protocol)
		if e.ContainerName != "" {
			dockerByPort[key] = e.ContainerName
		}
	}
	proxied := make(map[string]bool) // keys whose docker entry was absorbed
	for i, e := range systemEntries {
		if e.ProcessName == "docker-proxy" {
			key := fmt.Sprintf("%d/%s", e.Port, e.Protocol)
			if name, ok := dockerByPort[key]; ok {
				systemEntries[i].ContainerName = name
				systemEntries[i].Source = "docker"
				proxied[key] = true
			}
		}
	}
	// Remove docker inspect entries that are already represented by a docker-proxy system entry.
	filtered := dockerEntries[:0]
	for _, e := range dockerEntries {
		key := fmt.Sprintf("%d/%s", e.Port, e.Protocol)
		if !proxied[key] {
			filtered = append(filtered, e)
		}
	}
	dockerEntries = filtered

	all := append(systemEntries, dockerEntries...)
	var kept []PortEntry
	for _, e := range all {
		if !*showAll && e.State == "CLOSE" {
			continue
		}
		if !*showAll && e.LocalAddress == "(container-only)" {
			continue
		}
		if !*show6 && isIPv6(e.LocalAddress) {
			continue
		}
		kept = append(kept, e)
	}
	all = kept
	sort.Slice(all, func(i, j int) bool {
		if all[i].Port != all[j].Port {
			return all[i].Port < all[j].Port
		}
		return all[i].Protocol < all[j].Protocol
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(all)
		return
	}


	for _, e := range errs {
		fmt.Fprintf(os.Stderr, color(dim, "[!] %s\n"), e)
	}

	renderAll(all)

	fmt.Println()
	fmt.Println(color(dim, fmt.Sprintf(
		"Total: %d system port(s), %d Docker binding(s).",
		len(systemEntries), len(dockerEntries),
	)))
	fmt.Println()
}
