package main

import (
	"flag"
	"fmt"
	"gomap/scan"
	"os"
	"strconv"
	"strings"
)

func main() {
	var (
		target        = flag.String("u", "", "Target host to scan (required)")
		ports         = flag.String("p", "1-1000", "Port range to scan (e.g., 80,443 or 1-100)")
		serviceDetect = flag.Bool("sV", false, "Enable service/version detection")
	)
	flag.Parse()

	if *target == "" {
		fmt.Println("Error: target is required")
		flag.Usage()
		os.Exit(1)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}
	scan.Scanner(*target, portList, *serviceDetect)
}

func parsePorts(portsFlag string) ([]int, error) {
	var ports []int

	// Split by comma
	ranges := strings.Split(portsFlag, ",")

	for _, r := range ranges {
		// Check if it's a range (contains "-")
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", parts[1])
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// Single port
			port, err := strconv.Atoi(strings.TrimSpace(r))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", r)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}
