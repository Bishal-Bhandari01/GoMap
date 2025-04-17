package services

import "regexp"

var commonPortProbes = map[int][]ServiceProbe{
	21: {
		{
			Name:        "FTP",
			ProbeString: "USER anonymous\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`^220[ -]([^\r\n]+)`), 1, "ftp", ""},
				{regexp.MustCompile(`^220 ([^\r\n]+) FTP`), 1, "ftp", ""},
			},
		},
	},
	22: {
		{
			Name:        "SSH",
			ProbeString: "SSH-2.0-GoScanner\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`SSH-(\d+\.\d+[^ -]*)`), 1, "ssh", ""},
				{regexp.MustCompile(`OpenSSH[_-]([^\r\n]+)`), 1, "ssh", ""},
			},
		},
	},
	23: {
		{
			Name:        "Telnet",
			ProbeString: "\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([^\r\n]+)`), 1, "telnet", ""},
			},
		},
	},
	25: {
		{
			Name:        "SMTP",
			ProbeString: "EHLO gomap\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`^220[ -]([^\r\n]+)`), 1, "smtp", ""},
				{regexp.MustCompile(`^220 ([^\r\n]+) ESMTP`), 1, "smtp", ""},
			},
		},
	},
	53: {
		{
			Name:  "DNS",
			Probe: []byte{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([^\r\n]+)`), 1, "dns", ""},
			},
		},
	},
	80: {
		{
			Name:        "HTTP",
			ProbeString: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`Server: ([^\r\n]+)`), 1, "http", ""},
				{regexp.MustCompile(`X-Powered-By: ([^\r\n]+)`), 1, "http", ""},
			},
		},
	},
	110: {
		{
			Name:        "POP3",
			ProbeString: "CAPA\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`^+OK ([^\r\n]+)`), 1, "pop3", ""},
			},
		},
	},
	143: {
		{
			Name:        "IMAP",
			ProbeString: "A001 CAPABILITY\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([^\r\n]+) IMAP`), 1, "imap", ""},
			},
		},
	},
	443: {
		{
			Name:        "HTTPS",
			ProbeString: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`Server: ([^\r\n]+)`), 1, "https", ""},
			},
		},
	},
	1433: {
		{
			Name:  "MSSQL",
			Probe: []byte{0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00},
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([^\r\n]+)`), 1, "mssql", ""},
			},
		},
	},
	3306: {
		{
			Name:  "MySQL",
			Probe: []byte{0x0a},
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`), 1, "mysql", ""},
			},
		},
	},
	5432: {
		{
			Name:        "PostgreSQL",
			ProbeString: "\x00\x00\x00\x08\x04\xd2\x16\x2f",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`PostgreSQL ([^\r\n]+)`), 1, "postgresql", ""},
			},
		},
	},
	6379: {
		{
			Name:        "Redis",
			ProbeString: "INFO\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`redis_version:([^\r\n]+)`), 1, "redis", ""},
			},
		},
	},
	8080: {
		{
			Name:        "HTTP-Proxy",
			ProbeString: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`Server: ([^\r\n]+)`), 1, "http-proxy", ""},
			},
		},
	},
	27017: {
		{
			Name:  "MongoDB",
			Probe: []byte{0x41, 0x00, 0x00, 0x00},
			Matches: []ProbeMatch{
				{regexp.MustCompile(`(?i)mongodb/([^\s]+)`), 1, "mongodb", ""},
			},
		},
	},
	11211: {
		{
			Name:        "Memcached",
			ProbeString: "version\r\n",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`VERSION ([^\r\n]+)`), 1, "memcached", ""},
			},
		},
	},
	5672: {
		{
			Name:        "RabbitMQ",
			ProbeString: "AMQP",
			Matches: []ProbeMatch{
				{regexp.MustCompile(`rabbitmq_version=([^\r\n]+)`), 1, "rabbitmq", ""},
			},
		},
	},
	161: {
		{
			Name:  "SNMP",
			Probe: []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04},
			Matches: []ProbeMatch{
				{regexp.MustCompile(`([^\r\n]+)`), 1, "snmp", ""},
			},
		},
	},
}
