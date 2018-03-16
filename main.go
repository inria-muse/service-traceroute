package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	Version = "0.1" // MAKE SURE TO INCREMENT AFTER EVERY CHANGE
)

type Experiment struct {
	ip                string
	port              int
	distance          int
	iterations        int
	sniffing          bool
	sendPackets       bool
	stopBorderRouters bool
	waitProbeReply    bool
}

var Experiments = []Experiment{
	Experiment{
		ip:                "128.93.101.87",
		port:              80,
		distance:          10,
		iterations:        2,
		sniffing:          true,
		sendPackets:       true,
		stopBorderRouters: true,
		waitProbeReply:    true,
	},
	Experiment{
		ip:                "193.51.224.142",
		port:              443,
		distance:          15,
		iterations:        3,
		sniffing:          true,
		sendPackets:       true,
		stopBorderRouters: true,
		waitProbeReply:    true,
	},
	Experiment{
		ip:                "198.38.120.152",
		port:              443,
		distance:          9,
		iterations:        4,
		sniffing:          true,
		sendPackets:       true,
		stopBorderRouters: true,
		waitProbeReply:    true,
	},
	Experiment{
		ip:                "198.38.120.154",
		port:              443,
		distance:          9,
		iterations:        4,
		sniffing:          true,
		sendPackets:       true,
		stopBorderRouters: true,
		waitProbeReply:    true,
	},
}

func checkFlags(version bool, iface string) {
	if version {
		fmt.Printf("%s\n", Version)
		os.Exit(0)
	}

	if iface == "" {
		panic("Interface not valid")
	}
}

func traceOut(outChan chan string) {
	for {
		select {
		case s := <-outChan:
			fmt.Printf("%s\n", s)
		}
	}
}

func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "print version and exit")

	var iface string
	flag.StringVar(&iface, "iface", "", "capture interface")

	flag.Parse()

	checkFlags(version, iface)

	outChan := make(chan string, 1000)

	go traceOut(outChan)

	traceTCPManager := new(TraceTCPManager)
	traceTCPManager.NewTraceTCPManager(iface, V4, nil)

	traceTCPManager.SetOutChan(outChan)

	traceTCPManager.AddBorderRouters(net.ParseIP("195.220.98.17"))

	//Start TraceTCPManager listener
	go traceTCPManager.Run()

	//start 3 TraceTCP flow
	for _, exp := range Experiments {
		go traceTCPManager.StartNewConfiguredTraceTCP(
			net.ParseIP(exp.ip),
			exp.port,
			exp.distance,
			exp.iterations,
			exp.sniffing,
			exp.sendPackets,
			exp.waitProbeReply,
			exp.stopBorderRouters,
		)
	}

	iT := time.NewTicker(time.Millisecond * 1000)
	for _ = range iT.C {
		if traceTCPManager.GetNumberOfRunningTraceTCP() <= 0 {
			iT.Stop()
		}
	}

	outChan <- "Finished"
}
