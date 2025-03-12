package main

import (
	"flag"
    "encoding/csv"
    "fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Command-line argument for PCAP file input
	pcapFile := flag.String("f", "", "Path to the PCAP file")
	flag.Parse()

	if *pcapFile == "" {
		log.Fatal("Usage: ./main.go -f <pcap_file>")
	}

	// Create zeek_logs directory if it doesn't exist
	logDir := "zeek_logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Error creating log directory: %v", err)
	}

	// Open the PCAP file
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening PCAP file: %v", err)
	}
	defer handle.Close()

	// Define log file path
	logPath := filepath.Join(logDir, "conn.log")

	// Create Zeek-style connection log file
	logFile, err := os.Create(logPath)
	if err != nil {
		log.Fatalf("Error creating conn.log: %v", err)
	}
	defer logFile.Close()

	// CSV writer for structured output
	writer := csv.NewWriter(logFile)
	defer writer.Flush()

	// Zeek-style header
	headers := []string{"ts", "src_ip", "src_port", "dst_ip", "dst_port", "protocol"}
	writer.Write(headers)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Extract network and transport layer data
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()

		if networkLayer == nil || transportLayer == nil {
			continue
		}

		srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
		srcPort, dstPort := transportLayer.TransportFlow().Endpoints()
		protocol := transportLayer.LayerType().String()

		// Write connection info in Zeek-style
		record := []string{
			fmt.Sprintf("%v", packet.Metadata().Timestamp.Unix()), // Timestamp
			srcIP.String(),
			srcPort.String(),
			dstIP.String(),
			dstPort.String(),
			protocol,
		}

		writer.Write(record)
	}

	fmt.Printf("PCAP successfully converted to Zeek-style logs in %s/\n", logDir)
}
