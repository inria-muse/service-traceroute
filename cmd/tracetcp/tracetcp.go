package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Experiment struct {
	ip                   string
	port                 int
	service              string
	distance             int
	iterations           int
	sniffing             bool
	sendPackets          bool
	stopBorderRouters    bool
	waitProbeReply       bool
	startWithEmptyPacket bool
}

var Experiments = []Experiment{
	Experiment{
		ip:                   "128.93.101.87",
		port:                 80,
		service:              "Youtube",
		distance:             10,
		iterations:           2,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: false,
	},
	Experiment{
		ip:                   "193.51.224.143",
		port:                 443,
		service:              "Youtube",
		distance:             15,
		iterations:           3,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: false,
	},
	Experiment{
		ip:                   "198.38.120.152",
		port:                 443,
		service:              "Youtube",
		distance:             9,
		iterations:           4,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: true,
	},
	Experiment{
		ip:                   "198.38.120.154",
		port:                 443,
		service:              "Youtube",
		distance:             9,
		iterations:           4,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: true,
	},
	Experiment{
		ip:                   "198.38.120.149",
		port:                 443,
		service:              "Youtube",
		distance:             9,
		iterations:           4,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: true,
	},
	Experiment{
		ip:                   "198.38.120.162",
		port:                 443,
		service:              "Youtube",
		distance:             9,
		iterations:           4,
		sniffing:             false,
		sendPackets:          false,
		stopBorderRouters:    true,
		waitProbeReply:       false,
		startWithEmptyPacket: true,
	},
}

func checkFlags(version bool, iface string) {
	if version {
		fmt.Printf("%s\n", tracetcp.Version)
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

	//Start Listeners and Sender
	queue := make(chan []gopacket.SerializableLayer, 1000)
	go startSender(iface, queue)

	tcpChanInputPkt, icmpChanInputPkt := startListener(iface, tracetcp.V4, outChan)

	tcpChan := make(chan gopacket.Packet, 1000)
	icmpChan := make(chan gopacket.Packet, 1000)

	go converter(tcpChanInputPkt, tcpChan, icmpChanInputPkt, icmpChan)

	traceTCPManager := new(tracetcp.TraceTCPManager)
	traceTCPManager.NewTraceTCPManager(iface, tracetcp.V4, nil)

	traceTCPManager.SetOutChan(outChan)

	traceTCPManager.AddBorderRouters(net.ParseIP("195.220.98.17"))

	traceTCPManager.SetOutPktsChan(queue)
	traceTCPManager.SetTCPInChan(tcpChan)
	traceTCPManager.SetICMPInChan(icmpChan)

	//Start TraceTCPManager listener
	go traceTCPManager.Run()

	//start 3 TraceTCP flow
	for _, exp := range Experiments {
		go traceTCPManager.StartNewConfiguredTraceTCP(
			net.ParseIP(exp.ip),
			exp.port,
			exp.service,
			exp.distance,
			exp.iterations,
			exp.sniffing,
			exp.sendPackets,
			exp.waitProbeReply,
			exp.stopBorderRouters,
			exp.startWithEmptyPacket,
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

func startListener(iface string, ipVersion string, outchan chan string) (chan tracetcp.InputPkt, chan tracetcp.InputPkt) {
	var TCPCapThread = tracetcp.CapThread{BPF: Tcp, Buffer: 10000, CapSize: 100}
	var ICMPCapThread = tracetcp.CapThread{BPF: Icmp, Buffer: 10000, CapSize: 1000}

	tcpChan := make(chan tracetcp.InputPkt, 1000)
	icmpChan := make(chan tracetcp.InputPkt, 1000)
	readyChan := make(chan bool)

	tcpHandler := new(PcapHandler)
	tcpHandler.NewPacketHandler(TCPCapThread, iface, ipVersion, "", 0, tcpChan, outchan, readyChan)
	go tcpHandler.Run()
	<-readyChan

	icmpHandler := new(PcapHandler)
	icmpHandler.NewPacketHandler(ICMPCapThread, iface, ipVersion, "", 0, icmpChan, outchan, readyChan)
	go icmpHandler.Run()
	<-readyChan

	return tcpChan, icmpChan
}

func startSender(iface string, sendQueue chan []gopacket.SerializableLayer) {
	handle, err := pcap.OpenLive(iface, int32(100), false, time.Duration(30*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	buf := gopacket.NewSerializeBuffer()

	for {
		select {
		case outPktL := <-sendQueue:

			buf.Clear()
			optsCSum := gopacket.SerializeOptions{
				ComputeChecksums: true,
			}

			for i := len(outPktL) - 1; i >= 0; i-- {
				layer := outPktL[i]
				opts := gopacket.SerializeOptions{}
				if tcpL, ok := layer.(*layers.TCP); ok {
					if i == 0 {
						log.Fatal(errors.New("TCP layer without IP Layer"))
					}
					if ipL, ok := outPktL[i-1].(*layers.IPv4); ok {
						if err = tcpL.SetNetworkLayerForChecksum(ipL); err != nil {
							log.Fatal(err)
						}
					}
					//TODO v6
					opts = optsCSum
				}
				if _, ok := layer.(*layers.IPv4); ok {
					opts = optsCSum
				}
				//TODO v6
				if err = layer.SerializeTo(buf, opts); err != nil {
					log.Fatal(err)
				}
			}

			if err = handle.WritePacketData(buf.Bytes()); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func converter(tcpChan chan tracetcp.InputPkt, tcpChanConverted chan gopacket.Packet, icmpChan chan tracetcp.InputPkt, icmpChanConverted chan gopacket.Packet) {
	for {
		select {
		case packet := <-tcpChan:
			tcpChanConverted <- packet.Packet
		case packet := <-icmpChan:
			icmpChanConverted <- packet.Packet
		}
	}
}
