package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	zeekLogsDir        = "zeek_logs"
	coreLogsDir        = "zeek_logs/core"
	networkServicesDir = "zeek_logs/network_services"
	applicationLogsDir = "zeek_logs/application"
)

var coreLogs = []string{"conn.log", "dns.log", "http.log", "files.log", "ssl.log"}
var networkLogs = []string{"ftp.log", "smtp.log", "ssh.log", "rdp.log", "ldap.log"}
var applicationLogs = []string{"pe.log", "ntp.log", "quic.log", "traceroute.log"}

func main() {
	pcapFile := flag.String("pcap", "", "Path to the input PCAP file")
	flag.Parse()

	if *pcapFile == "" {
		fmt.Println("Usage: go run main.go -pcap <pcap_file>")
		os.Exit(1)
	}

	absPcapFile, err := filepath.Abs(*pcapFile)
	if err != nil {
		fmt.Println("Error getting absolute path:", err)
		os.Exit(1)
	}

	if _, err := os.Stat(absPcapFile); os.IsNotExist(err) {
		fmt.Println("Error: PCAP file does not exist:", absPcapFile)
		os.Exit(1)
	}

	createZeekDirectories()

	if err := runZeek(absPcapFile); err != nil {
		fmt.Println("Zeek processing failed:", err)
		os.Exit(1)
	}

	categorizeLogs()

	fmt.Println("Zeek logs generated in:", zeekLogsDir)
}

func createZeekDirectories() {
	dirs := []string{coreLogsDir, networkServicesDir, applicationLogsDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Println("Error creating directory:", dir, "-", err)
			os.Exit(1)
		}
	}
}

func runZeek(pcap string) error {
	cmd := exec.Command("zeek", "-r", pcap)
	cmd.Dir = zeekLogsDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func categorizeLogs() {
	files, err := os.ReadDir(zeekLogsDir)
	if err != nil {
		fmt.Println("Error reading Zeek log directory:", err)
		return
	}

	for _, file := range files {
		filePath := filepath.Join(zeekLogsDir, file.Name())
		var targetDir string

		switch {
		case contains(coreLogs, file.Name()):
			targetDir = coreLogsDir
		case contains(networkLogs, file.Name()):
			targetDir = networkServicesDir
		case contains(applicationLogs, file.Name()):
			targetDir = applicationLogsDir
		default:
			targetDir = zeekLogsDir
		}

		newPath := filepath.Join(targetDir, file.Name())
		if err := os.Rename(filePath, newPath); err != nil {
			fmt.Println("Error moving file:", file.Name(), "to", targetDir, "-", err)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
