package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"
)

const (
	Version = "0.1" // MAKE SURE TO INCREMENT AFTER EVERY CHANGE
)

const (
	V4   = "4"
	V6   = "6"
	Tcp  = "tcp"
	Icmp = "icmp"
)

type CapThread struct {
	BPF     string
	Buffer  int
	CapSize int
}

var capThreads = []CapThread{CapThread{BPF: Tcp, Buffer: 10000, CapSize: 100},
	CapThread{BPF: Icmp, Buffer: 10000, CapSize: 1000}}

func checkFlags(version bool, iface string, proto string, ip string, port int) {
	if version {
		fmt.Printf("%s\n", Version)
		os.Exit(0)
	}

	if iface == "" {
		panic("Interface not valid")
	}

	if proto != V4 && proto != V6 {
		panic("Bad IP Protocol")
	}

	if netIp := net.ParseIP(ip); netIp == nil {
		panic("Bad IP address")
	} else {
		if proto == V4 && netIp.To4() == nil {
			panic("Bad IP address")
		}
	}

	if port < 0 || port > math.MaxInt16 {
		panic("Bad port")
	}
}

func traceOut(outChan chan string) {
	for {
		select {
		case s := <-outChan:
			fmt.Printf("%s", s)
		}
	}
}

func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "print version and exit")

	var iface string
	flag.StringVar(&iface, "iface", "", "capture interface")

	var proto string
	flag.StringVar(&proto, "proto", V4, "IP version")

	var ip string
	flag.StringVar(&ip, "ip", "", "IP address to trace")

	var port int
	flag.IntVar(&port, "port", 0, "port to trace")

	flag.Parse()

	checkFlags(version, iface, proto, ip, port)

	outChan := make(chan string, 1000)
	done := make(chan bool)
	pktChan := make(chan InputPkt, 100000)

	go traceOut(outChan)

	var localV4, localV6 net.IP
	for _, thread := range capThreads {
		ph := new(PcapHandler)
		ph.NewPacketHandler(thread, iface, proto, ip, port, pktChan, outChan, done)
		localV4 = ph.LocalV4
		localV6 = ph.LocalV6
		go ph.Run()
	}
	pa := new(PacketAnalyzer)
	pa.NewPacketAnalyzer(pktChan, localV4, localV6)
	pa.Run()

	<-done
}
