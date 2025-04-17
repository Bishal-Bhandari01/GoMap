package services

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type ServiceInfo struct {
	Name        string
	Port        int
	Protocol    string
	Description string
}

var ServiceMap map[int]ServiceInfo

func init() {
	ServiceMap = make(map[int]ServiceInfo)
	loadServices("/usr/share/nmap/nmap-services")
}

func loadServices(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || len(strings.TrimSpace(line)) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		portProto := strings.Split(fields[1], "/")
		if len(portProto) != 2 {
			continue
		}

		port, err := strconv.Atoi(portProto[0])
		if err != nil {
			continue
		}

		description := ""
		if len(fields) > 3 {
			description = strings.Join(fields[3:], " ")
		}

		ServiceMap[port] = ServiceInfo{
			Name:        fields[0],
			Port:        port,
			Protocol:    portProto[1],
			Description: description,
		}
	}

	return scanner.Err()
}

func GetService(port int) ServiceInfo {
	if service, exists := ServiceMap[port]; exists {
		return service
	}
	return ServiceInfo{Name: "unknown"}
}
