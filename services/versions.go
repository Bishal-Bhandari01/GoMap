package services

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"time"
)

const probeTimeout = 5 * time.Second // Define a timeout duration for probes

type ProbeResult struct {
	Port     int
	Service  string
	Version  string
	Banner   string
	Protocol string
	Info     string
	Error    error
}

type ServiceProbe struct {
	Name        string
	Probe       []byte
	ProbeString string
	Matches     []ProbeMatch
	Ports       []int
	SSLPorts    []int
	Rarity      int
}

type ProbeMatch struct {
	Pattern      *regexp.Regexp
	VersionIndex int
	ServiceName  string
	Info         string
}

// Common probe patterns for various services
var serviceProbes = []ServiceProbe{
	{
		Name:        "NULL",
		ProbeString: "",
		Matches: []ProbeMatch{
			{regexp.MustCompile(`(?i)^SSH-([.\d]+)`), 1, "ssh", ""},
			{regexp.MustCompile(`(?i)^220[ -]([^\r\n]*FTP)`), 1, "ftp", ""},
			{regexp.MustCompile(`^VER[ =]([^\r\n]*)`), 1, "", ""},
		},
	},
	{
		Name:        "GenericLines",
		ProbeString: "\r\n\r\n",
		Matches: []ProbeMatch{
			{regexp.MustCompile(`^HTTP/[\d.]+\s+(\d+)`), 1, "http", ""},
			{regexp.MustCompile(`^SMTP`), 0, "smtp", ""},
			{regexp.MustCompile(`^SSH-\d\.\d-`), 0, "ssh", ""},
		},
	},
	{
		Name:        "GetRequest",
		ProbeString: "GET / HTTP/1.0\r\n\r\n",
		Matches: []ProbeMatch{
			{regexp.MustCompile(`Server: ([^\r\n]+)`), 1, "http", ""},
			{regexp.MustCompile(`X-Powered-By: ([^\r\n]+)`), 1, "http", ""},
		},
	},
	{
		Name:        "HTTPOptions",
		ProbeString: "OPTIONS / HTTP/1.0\r\n\r\n",
		Matches: []ProbeMatch{
			{regexp.MustCompile(`Server: ([^\r\n]+)`), 1, "http", ""},
		},
	},
	{
		Name:        "RTSPRequest",
		ProbeString: "DESCRIBE rtsp://hello RTSP/1.0\r\n\r\n",
		Matches: []ProbeMatch{
			{regexp.MustCompile(`^RTSP/\d\.\d`), 0, "rtsp", ""},
		},
	},
	{
		Name:  "DNSVersionBindReq",
		Probe: []byte{0x00, 0x00, 0x10, 0x00, 0x00},
		Matches: []ProbeMatch{
			{regexp.MustCompile(`(?i)^bind\.\d+\.\d+`), 0, "dns", ""},
		},
	},
}

func DetectVersion(conn net.Conn, port int) string {
	// Set timeout for version detection
	conn.SetDeadline(time.Now().Add(probeTimeout))

	// Get probe for specific port
	probes, exists := commonPortProbes[port]
	if !exists {
		return ""
	}

	// Try each probe
	for _, probe := range probes {
		// Send probe
		if probe.ProbeString != "" {
			if _, err := conn.Write([]byte(probe.ProbeString)); err != nil {
				continue
			}
		} else if len(probe.Probe) > 0 {
			if _, err := conn.Write(probe.Probe); err != nil {
				continue
			}
		}

		// Read response with timeout
		buffer := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buffer)
		if err != nil {
			continue
		}

		// Try to match version
		response := buffer[:n]
		for _, match := range probe.Matches {
			if matches := match.Pattern.FindSubmatch(response); len(matches) > match.VersionIndex {
				return string(matches[match.VersionIndex])
			}
		}
	}

	return ""
}

func sendProbe(conn net.Conn, port int, probe ServiceProbe) ProbeResult {
	result := ProbeResult{
		Port: port,
	}

	// Send probe data
	if len(probe.Probe) > 0 {
		conn.Write(probe.Probe)
	} else if probe.ProbeString != "" {
		conn.Write([]byte(probe.ProbeString))
	}

	// Read response
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 4096)
	n, err := reader.Read(buffer)
	if err != nil {
		result.Error = err
		return result
	}

	response := buffer[:n]
	result.Banner = string(response)

	// Try to match response against patterns
	for _, match := range probe.Matches {
		if matches := match.Pattern.FindSubmatch(response); len(matches) > match.VersionIndex {
			if match.ServiceName != "" {
				result.Service = match.ServiceName
			}
			if match.VersionIndex > 0 {
				result.Version = string(matches[match.VersionIndex])
				result.Version = cleanVersionString(result.Version)
			}
			if match.Info != "" {
				result.Info = match.Info
			}
			break
		}
	}

	return result
}

func cleanVersionString(version string) string {
	// Remove common prefixes and suffixes
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "version ")
	version = strings.TrimPrefix(version, "Version ")
	version = strings.TrimSuffix(version, "\r")
	version = strings.TrimSuffix(version, "\n")

	// Remove anything after certain characters
	if idx := strings.Index(version, " "); idx != -1 {
		version = version[:idx]
	}

	return version
}
