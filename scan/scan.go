package scan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Bishal-Bhandari01/GoMap/services"
)

const (
	maxWorkers   = 1000 // Increase number of workers
	dialTimeout  = 2 * time.Second
	probeTimeout = 3 * time.Second
	debugMode    = false // Set to true for verbose logging
)

type PortState string

const (
	StateOpen       PortState = "open"
	StateClosed     PortState = "closed"
	StateFiltered   PortState = "filtered"
	StateTCPWrapped PortState = "tcpwrapped"
)

type ScanResult struct {
	Port    int
	State   PortState
	Service string
	Version string
}

func Scanner(target string, ports []int, serviceDetect bool) {
	startTime := time.Now()
	results := make([]ScanResult, 0)
	resultsChan := make(chan ScanResult, len(ports))

	// Check if ports were specified as a comma-separated list
	isSpecificPorts := len(ports) < 50 // Arbitrary threshold to identify specific ports list

	// Create worker pool
	pool := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			pool <- struct{}{}
			defer func() { <-pool }()

			address := formatAddress(target, p)
			result := ScanResult{
				Port:  p,
				State: StateFiltered, // Default state
			}

			conn, err := net.DialTimeout("tcp", address, dialTimeout)
			if err != nil {
				if isSpecificPorts {
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						result.State = StateFiltered
					} else {
						result.State = StateClosed
					}
					resultsChan <- result
				}
				return
			}
			defer conn.Close()

			result.State = StateOpen

			if serviceDetect {
				if service := services.GetService(p); service.Name != "" {
					result.Service = service.Name
					if v := services.DetectVersion(conn, p); v != "unknown" {
						if v == "tcpwrapped" {
							result.State = StateTCPWrapped
						} else {
							result.Version = v
						}
					}
				}
			}

			resultsChan <- result
		}(port)
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		if isSpecificPorts || result.State == StateOpen {
			results = append(results, result)
		}
	}

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	displayResults(target, results, serviceDetect, startTime, isSpecificPorts)
}

func formatAddress(target string, port int) string {
	ip := net.ParseIP(target)
	if ip == nil {
		// Treat as hostname
		return fmt.Sprintf("%s:%d", target, port)
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", target, port) // IPv6
	}
	return fmt.Sprintf("%s:%d", target, port) // IPv4
}

func displayResults(target string, results []ScanResult, serviceDetect bool, startTime time.Time, showAllStates bool) {
	fmt.Printf("\nStarting GoMap scan at %s\n", startTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("Scan report for %s\n\n", target)

	if serviceDetect {
		fmt.Println("PORT          STATE       SERVICE     VERSION")
		fmt.Println("------------------------------------------------")
		for _, result := range results {
			fmt.Printf("%-13s %-11s %-11s %-15s\n",
				fmt.Sprintf("%d/tcp", result.Port),
				result.State,
				result.Service,
				result.Version)
		}
	} else {
		fmt.Println("PORT          STATE       SERVICE")
		fmt.Println("-----------------------------------")
		for _, result := range results {
			fmt.Printf("%-13s %-11s %-11s\n",
				fmt.Sprintf("%d/tcp", result.Port),
				result.State,
				result.Service)
		}
	}

	if len(results) == 0 {
		fmt.Println("No ports found")
	}

	fmt.Printf("\nScan completed at %s\n", time.Now().Format("2006-01-02 15:04:05"))
}
