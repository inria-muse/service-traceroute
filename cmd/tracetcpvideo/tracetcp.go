package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"tracetcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	Youtube = "Youtube"
	Netflix = "Netflix"
)

const (
	Version  = "0.2" // MAKE SURE TO INCREMENT AFTER EVERY CHANGE
	FileConf = "planetlab/input.conf"
)

type InJson struct {
	CapThreads []tracetcp.CapThread
	Services   []Service
	HoA        HoAConf
}

type HoAConf struct {
	Active                  bool
	UpstreamIf              string
	TracerouteDestination   string
	TraceroutePeriod        int
	ServiceTraceroutePeriod int
	AccessProbing           ProbingConf
	WirelessProbing         ProbingConf
}

type ProbingConf struct {
	TrafficLThreshold int
	TrafficUThreshold int
	PingPeriod        int
	PingLength        int
	Gamma             int
	Train             int
	TrainInterval     int
	SizePattern       []int
}

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

	var distance int
	flag.IntVar(&distance, "d", 8, "distance")

	var iterations int
	flag.IntVar(&iterations, "i", 3, "iterations")

	flag.Parse()

	checkFlags(version, iface)

	ts := new(TrafficStats)
	ts.NewTrafficStats(loadServices())

	outChan := make(chan string, 1000)

	go traceOut(outChan)

	//Start Listeners and Sender
	queue := make(chan []gopacket.SerializableLayer, 1000)
	go startSender(iface, queue)

	tcpFlowManagerChan, icmpChan, dnsChanInputPkt := startListener(iface, tracetcp.V4, outChan)

	go DNSListener(dnsChanInputPkt, ts)

	traceTCPChan := make(chan gopacket.Packet, 1000)

	traceTCPManager := new(tracetcp.TraceTCPManager)
	traceTCPManager.NewTraceTCPManager(iface, tracetcp.V4, nil)

	traceTCPManager.SetOutChan(outChan)

	//traceTCPManager.AddBorderRouters(net.ParseIP("195.220.98.17"))

	traceTCPManager.SetOutPktsChan(queue)
	traceTCPManager.SetTCPInChan(traceTCPChan)
	traceTCPManager.SetICMPInChan(icmpChan)

	//Start TraceTCPManager listener
	go traceTCPManager.Run()

	go flowManager(traceTCPManager, ts, tcpFlowManagerChan, traceTCPChan, outChan, distance, iterations)

	//start 3 TraceTCP flow
	// for _, exp := range Experiments {
	// 	go traceTCPManager.StartNewConfiguredTraceTCP(
	// 		net.ParseIP(exp.ip),
	// 		exp.port,
	// 		exp.service,
	// 		exp.distance,
	// 		exp.iterations,
	// 		exp.sniffing,
	// 		exp.sendPackets,
	// 		exp.waitProbeReply,
	// 		exp.stopBorderRouters,
	// 		exp.startWithEmptyPacket,
	// 	)
	// }

	for {
		time.Sleep(5 * time.Second)
	}
}

func flowManager(manager *tracetcp.TraceTCPManager, ta *TrafficStats, tcpChan chan gopacket.Packet, traceTCPChan chan gopacket.Packet, outChan chan string, distance int, iterations int) {
	//TODO: REMOVE DEBUG CHECKS (getlog)
	println("Starting FlowManager")
	for {
		select {
		case pkt := <-tcpChan:
			traceTCPChan <- pkt
			dstIP, err := GetDstIPv4(&pkt)

			//check if we got any error on getting the dst IP
			if err != nil {
				outChan <- err.Error()
				continue
			}

			dstPort, err := GetDstPort(&pkt)

			//check if we got any error on getting the dst Port
			if err != nil {
				outChan <- err.Error()
				continue
			}

			//check if there log is still existing in manager
			if _, err := manager.GetLog(dstIP.String()); err == nil {
				continue
			}

			ta.MapMutex.Lock()
			//check if there is any corresponding IP in the DNS lookup
			if _, ok := ta.IpLookup[dstIP.String()]; !ok {
				ta.MapMutex.Unlock()
				continue
			}
			dns := ta.IpLookup[dstIP.String()]
			//println("IP found in the IPLookup of service " + dns.Name)
			ta.MapMutex.Unlock()

			//if it is a video, start tracetcp
			if dns.Name == Youtube || dns.Name == Netflix {
				exp := Experiment{
					ip:                   dstIP.String(),
					port:                 dstPort,
					service:              dns.Name,
					distance:             distance,
					iterations:           iterations,
					sniffing:             false,
					sendPackets:          false,
					stopBorderRouters:    true,
					waitProbeReply:       true,
					startWithEmptyPacket: true,
				}
				fmt.Sprintf("Starting %s", exp.ip)

				go func() {
					//outChan <- "Starting TraceTCP to " + exp.ip
					err := manager.StartNewConfiguredTraceTCP(
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

					if err != nil {
						//outChan <- err.Error()
					}
				}()

			}

		}
	}
}

func startListener(iface string, ipVersion string, outchan chan string) (chan gopacket.Packet, chan gopacket.Packet, chan gopacket.Packet) {
	var TCPCapThread = tracetcp.CapThread{BPF: tracetcp.Tcp, Buffer: 100, CapSize: 1000}
	var ICMPCapThread = tracetcp.CapThread{BPF: tracetcp.Icmp, Buffer: 100, CapSize: 1000}
	var DNSCapThread = tracetcp.CapThread{BPF: tracetcp.Udp, Buffer: 100, CapSize: 1000}

	tcpChan := make(chan gopacket.Packet, 1000)
	icmpChan := make(chan gopacket.Packet, 1000)
	dnsChan := make(chan gopacket.Packet, 1000)
	readyChan := make(chan bool)

	tcpHandler := new(PcapExt)
	tcpHandler.NewPacketHandler(TCPCapThread, iface, ipVersion, "", 443, tcpChan, outchan, readyChan)
	go tcpHandler.Run()
	<-readyChan

	icmpHandler := new(PcapExt)
	icmpHandler.NewPacketHandler(ICMPCapThread, iface, ipVersion, "", 0, icmpChan, outchan, readyChan)
	go icmpHandler.Run()
	<-readyChan

	dnsHandler := new(PcapExt)
	dnsHandler.NewPacketHandler(DNSCapThread, iface, ipVersion, "", 53, dnsChan, outchan, readyChan)
	go dnsHandler.Run()
	<-readyChan

	return tcpChan, icmpChan, dnsChan
}

func DNSListener(dnsChan chan gopacket.Packet, ts *TrafficStats) {
	println("Starting DNS listener")

	for {
		select {
		case pkt := <-dnsChan:
			err := ts.ParseDnsLayer(pkt)

			if err != nil {
				print(err.Error())
			}
		}
	}

}

func loadServices() []Service {
	inputF := FileConf
	conf := InJson{}
	if sf, err := ioutil.ReadFile(inputF); err == nil {
		if err = json.Unmarshal(sf, &conf); err != nil {
			panic("Error reading " + inputF + " : " + err.Error())
		}
	} else {
		panic(inputF + " could not be found.")
	}
	return conf.Services
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

func GetDstIPv4(pkt *gopacket.Packet) (net.IP, error) {
	if ip4Layer := (*pkt).Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		return ip4Layer.(*layers.IPv4).DstIP, nil
	}
	return nil, errors.New("Not IPv4")
}

func GetDstPort(pkt *gopacket.Packet) (int, error) {
	if tcpLayer := (*pkt).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		dstPort := tcpLayer.(*layers.TCP).DstPort.String()
		dstPort = strings.Split(dstPort, "(")[0]
		return strconv.Atoi(dstPort)
	}
	return 0, errors.New("Not TCP")
}
