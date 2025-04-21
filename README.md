# GoMap - Fast Port Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/Bishal-Bhandari01/GoMap)](https://goreportcard.com/report/github.com/Bishal-Bhandari01/GoMap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A concurrent port scanner written in Go that performs service detection and version identification. Inspired by Nmap but built for simplicity and speed.

---

## ⚠️ Warning

**This project is currently in active development and BETA stage.**

Known limitations and issues:
- Service version detection may be incomplete or inaccurate
- Performance optimizations are still ongoing
- Limited test coverage
- May trigger IDS/IPS systems
- Not recommended for production use without thorough testing

---

## Features

- Fast concurrent port scanning
- Service version detection (-sV)
- Multiple port states (open, closed, filtered, tcpwrapped)
- Support for specific port lists and ranges
- IPv4 and IPv6 support

---

## Installation

```bash
# Install via go
go install github.com/Bishal-Bhandari01/GoMap/gomap@latest  

# Or clone the repository
git clone https://github.com/Bishal-Bhandari01/gomap.git
cd gomap
go build
```

---

## Quick Start

```bash
# Basic scan
./gomap -u scanme.nmap.org -p 80,443

# Full service version detection
./gomap -u scanme.nmap.org -p 1-1000 -sV
```

---

## Example Output

Specific ports scan:
```
Starting GoMap scan at 2025-04-17 16:30:45
Scan report for scanme.nmap.org

PORT          STATE       SERVICE     VERSION
------------------------------------------------
22/tcp        open       ssh         OpenSSH 8.4p1
80/tcp        open       http        nginx/1.18.0
443/tcp       filtered   https       
8080/tcp      closed     http-proxy  
```

Range scan (only shows open ports):
```
Starting GoMap scan at 2025-04-17 16:30:45
Scan report for scanme.nmap.org

PORT          STATE       SERVICE     VERSION
------------------------------------------------
22/tcp        open       ssh         OpenSSH 8.4p1
80/tcp        open       http        nginx/1.18.0
443/tcp       open       https       Apache/2.4.51
```

---

## Command Line Options

- `-u`: Target URL or IP address (required)
- `-p`: Port specification (e.g., 80,443 or 1-1000)
- `-sV`: Enable service version detection

---

## Debugging

Set debug mode in scan.go:
```go
const debugMode = true
```

Common issues:
1. "too many open files" error:
```bash
ulimit -n 4096
```

2. Slow scans:
- Reduce maxWorkers in scan.go
- Check network connectivity
- Verify target is responsive

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Development

```bash
# Clone the repository
git clone https://github.com/Bishal-Bhandari01/gomap.git

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build the project
go build
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

Name - [@Bishal-Bhandari01](https://github.com/Bishal-Bhandari01)

Project Link: [https://github.com/Bishal-Bhandari01/gomap](https://github.com/Bishal-Bhandari01/gomap)

---

## Acknowledgments

- Inspired by Nmap
- Uses Go's concurrent features for performance
- Community contributions welcome

---

## Security Notice

Please ensure you have permission to scan the target systems. Unauthorized scanning may be illegal in your jurisdiction.
