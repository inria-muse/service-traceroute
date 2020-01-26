package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/inria-muse/service-traceroute/pkg/servicetraceroute"
)

func traceOut(outChan chan string, resChan chan servicetraceroute.ServiceTracerouteJson, output string) {
	for {
		select {
		case s := <-outChan:
			fmt.Printf("%s\n", s)
		case res := <-resChan:
			if strings.ToLower(output) == "json" {
				out, _ := json.Marshal(res)

				fmt.Println(string(out))
				continue
			}
			fmt.Printf("%s Traceroute of service %s to %s (%s) with DstPort: %d and SrcPort: %d\n",
				strings.ToUpper(res.Data.TransportProtocol),
				res.Data.Service,
				res.Data.IPResolution,
				res.Data.TargetIP,
				res.Data.TargetPort,
				res.Data.LocalPort,
			)
			fmt.Printf("Probing algorithm: %s\n", res.Data.ProbingAlgorithm)
			fmt.Printf("Version %s\n", res.Info.Version)

			if len(res.Data.HopIPs) <= 0 {
				fmt.Sprintf("Flow closed before the probing phase")
			}
			for i, _ := range res.Data.HopIPs {
				ips := res.Data.HopIPs[i]
				rttarray := res.Data.Rtts[i]

				if len(ips) <= 0 {
					if i == 0 {
						fmt.Sprintf("Flow closed before the probing phase")
					}
					break
				}

				fmt.Printf(" %d: ", i+1)
				prevIP := ""
				for j, _ := range ips {
					if ips[j] != prevIP {
						fmt.Printf("(%s) %g ", ips[j], rttarray[j])
					} else {
						fmt.Printf("%g ", rttarray[j])
					}
					prevIP = ips[j]

				}
				for j := len(ips); j < res.Data.Iterations; j++ {
					fmt.Printf("* ")
				}
				fmt.Printf("\n")
			}

			if res.Data.ReachedFlowTimeout {
				fmt.Printf("FLOW TIMEOUT: No packets exchanged for more than %d milliseconds\n", res.Data.FlowTimeout)
			}
			if res.Data.FlowEnded {
				fmt.Printf("FLOW ENDED: The application flow ended earlier\n")
			}
			if res.Data.ReachedBorderRouter {
				fmt.Println("BORDER ROUTER reached")
			}
			if res.Data.ReachedMaxConsecutiveMissingHops {
				fmt.Println("Reached maximum of consecutive non replying hops")
			}

			fmt.Printf("\n\n")

		}
	}
}

func sniffer(iface string, tcp chan gopacket.Packet, udp chan gopacket.Packet, icmp chan gopacket.Packet, dns chan gopacket.Packet, outChan chan string) {
	//In this case, for keeping the code as simple as possible, we rely on the same module used by the library
	//However it can be easily changed with a simple code which sniff the packets from the interface and give them directly to the channels, since they are in the same format of the channel packets
	//Listeners manage easily multiple sniffers designed for Service Traceroute
	listeners := new(servicetraceroute.Listeners)
	listeners.NewListeners(iface, outChan)
	//These functions open a new thread running the sniffer for each protocol
	listeners.StartTCP(tcp)
	listeners.StartUDP(udp)
	listeners.StartICMP(icmp)
	listeners.StartDNS(dns)
	//These functions can be substituted with functions using this code:
	// packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// for packet := range packetSource.Packets() {
	// 	pktChan <- packet
	// }
	//Where pktChan can be one of the 4 channels: tcp, udp, icmp or dns
}

func sender(iface string, outPkt chan []byte) {
	//Differently from sniffer, the code to send a packet is quite small
	//The idea is to open the sniffer through the pcap library and using an infinite loop, check if there are packets in the queue to transmit
	handle, err := pcap.OpenLive(iface, int32(100), false, time.Duration(30*time.Second))

	//In case of error, exit!
	if err != nil {
		log.Fatal(err)
	}

	//Check forever if there are packets to send
	for {
		select {
		//If there is one, transmit it!
		case outPkt := <-outPkt:
			if err = handle.WritePacketData(outPkt); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func main() {
	//Initial configuration required for initializing traceTCPManager
	iface := "en0"                                       //Interface to use for sniffing and trasmissions
	ipVersion := servicetraceroute.V4                    //IP version, now supported only IPv4
	sameDestination := true                              //Flag to say if Service Traceroute has to traceroute multiple flows with the same end hosts
	samePort := true                                     //Flag to say if Service Traceroute should traceroute multiple flows with the same remote port and end hosts
	startTraceroutes := true                             //Mostly for debug or other purposes. Flag to say whether Service Traceroute should send probes or not. Useful to only discover application flows
	interTraceTime := 600                                //Time between traceroutes to the same application flow [seconds]
	maxMissingHops := 3                                  //Maximum number of consecutive non replying hops to stop a traceroute
	services := []string{"netflix", "youtube", "twitch"} //Services that Service Traceroute can traceroute automatically. There are other possible services and others can be added

	outChan := make(chan string, 1000)                                    //Channel to send stdout messages
	reportChan := make(chan servicetraceroute.ServiceTracerouteJson, 100) //Channel to return the results

	go traceOut(outChan, reportChan, "traceroute") //Just an example, it starts a thread used to print text and results on the stdout

	borderIPs := []net.IP{net.ParseIP("1.1.1.1")} //Example of array containing border routers. Border routers stop the traceroute when they are discovered.

	//Initialize a new trace TCP manager
	traceTCPManager := new(servicetraceroute.ServiceTracerouteManager)

	startSniffer := false //Set to true to use the sniffer of the library
	startSender := false  //Set to true to use the sender of the library
	startDNS := false     //Set to true to use the DNS listener. If set to false, ServiceTraceroute is able only to traceroute IPs

	//Call the constructor to give the initial configuration
	traceTCPManager.NewServiceTracerouteManager(iface, ipVersion, sameDestination, samePort, startSniffer, startSender, startDNS, startTraceroutes, interTraceTime, maxMissingHops, borderIPs, outChan, reportChan)

	//Service Traceroute can stop when some IPs are detected. This feature is useful when the traceroute should not go beyond a specific border, to avoid troubles with the receiver or with the network manager
	//The border routers can be set one by one using AddBorderRouters or in an array when calling the constructor of Service Traceroute
	//Or all at once by giving an external file
	traceTCPManager.AddBorderRouters(net.ParseIP("195.220.98.17"))
	traceTCPManager.LoadBorderRouters("border_routers.txt")

	//If startSniffer is false, traceTCPManager needs the incoming packets from an external module.
	//It is possible to use the channels initialized by traceTCPManager or by assigning new ones through the get&set

	tcpChan := traceTCPManager.GetTCPInChan()
	udpChan := traceTCPManager.GetUDPInChan()
	icmpChan := traceTCPManager.GetICMPInChan()

	//To modify the channels:
	// traceTCPManager.SetTCPInChan(traceTCPChan)
	// traceTCPManager.SetUDPInChan(traceUDPChan)
	// traceTCPManager.SetICMPInChan(icmpChan)

	//If the goal is to still use the DNS resolution but with an external management of the channels, like with the previous protocol
	//Then it is possible to start the 'custom' DNS channel and run the DNS resolution
	dnsChan := make(chan gopacket.Packet, 100)
	//It is suggested to set startDNS to false and then start it through this function
	traceTCPManager.StartDNSResolver(dnsChan)

	//In this example, we rely on sniffer to run the threads for each channel
	sniffer(iface, tcpChan, udpChan, icmpChan, dnsChan, outChan)

	//If startSender is false, the traceTCPManager needs a module to transmit the packets to the interface
	//Similarly with the previous channels, also the one for sending out packets can be obtained / modified through get & set
	outPacketsChan := traceTCPManager.GetOutPktsChan()

	//To modify the channel
	//traceTCPManager.SetOutPktsChan(queue)

	//Run sender on the channel
	go sender(iface, outPacketsChan)

	//It is possible to specify services to traceroute
	//For detecting automatically a specific online application like Netflix or Youtube, it is required to set the startDNS to true

	//Service Traceroute has the ability to start automatically the traceroute towards specific services like Youtube, Netflix, etc. when new application flows are detected
	//In order to traceroute them automatically, startDNS must be true
	//For each service, it is possible to specify the configuration for the traceroutes
	confHash := "id"                                 //Only an hash to identify the results
	distance := 32                                   //Maximum distance to probe
	interIterationTime := 100                        //Time to wait between each iteration (change of TTL) [us]
	interProbeTime := 100                            //Time to wait between each pair of probe [us]
	iterations := 3                                  //Number of probes per hops
	probingAlgorithm := servicetraceroute.Concurrent //Probing algorithm: PacketByPacket send 1 packet and wait a reply, HopByHop send all probes with the same TTL and then wait the replies, Concurrent send all probes at the end and then wait the replies
	emptyPacket := true                              //Specify whether Service Traceroute can start when an empty packet is detected. Otherwise it is required a packet with a layer 5 payload
	timeout := 2000                                  //Timeout before considering a probe lost [ms]
	flowTimeout := 60000                             //Maximum time of an idle period before considering a flow dead

	for _, service := range services {
		traceTCPManager.AddService(servicetraceroute.ServiceConfiguration{
			ConfHash:             confHash,
			Distance:             distance,
			InterIterationTime:   interIterationTime,
			InterProbeTime:       interProbeTime,
			Iterations:           iterations,
			ProbingAlgorithm:     probingAlgorithm,
			Service:              service,
			StartWithEmptyPacket: emptyPacket,
			Timeout:              timeout,
			FlowTimeout:          flowTimeout,
		})
	}

	//Since not all services are implemented, it is possible to add (or extend) new services just by specifying the IPs and URLs, which are associated to the specific service
	//However, to use URLs it is required to enable the DNS resolution
	//While, ips can be used even without DNS
	urls := make([]string, 0) //URLs to traceroute
	ips := make([]string, 0)  //IPs to traceroute

	traceTCPManager.AddService(servicetraceroute.ServiceConfiguration{
		ConfHash:             "",
		Distance:             distance,
		InterIterationTime:   interIterationTime,
		InterProbeTime:       interProbeTime,
		Iterations:           iterations,
		ProbingAlgorithm:     probingAlgorithm,
		Service:              "newservice",
		URLs:                 urls,
		IPPrefixes:           ips,
		StartWithEmptyPacket: emptyPacket,
		Timeout:              timeout,
		FlowTimeout:          flowTimeout,
	})

	//However, if the goal is to start only one traceroute for a specific application flow, it is possible to use StartTraceroute
	//If there aren't any other traceroute to the same application flow, it will start a new traceroute with the given configuration
	//It is possible to keep in memory a traceroute for some time, to avoid to run multiple traceroutes to the same target application flow in a small interval of time, set during the initialization of traceTCPManager

	transportProtocol := servicetraceroute.Tcp //It is possible to specify the transport protocol to use (UDP or TCP). In this way, also application relying on UDP can be probed
	remoteIP := net.ParseIP("8.8.8.8")
	remotePort := 403
	localPort := 12345
	service := "custom"
	ipresolution := ""
	maxDistance := 32
	numberIterations := 3
	interIterationTime = 100
	stopWithBorderRouters := false
	startWithEmptyPacket := true
	maxConsecutiveMissingHops := 3

	//StartTraceroute will lock the thread until it ends the traceroute
	//In order to start it without locking the main thread, just run it with go
	go traceTCPManager.StartTraceroute(
		transportProtocol,         //Transport Protocol: UDP or TCP
		remoteIP,                  //remote IP of the application flow
		remotePort,                //remote port of the application flow
		localPort,                 //local port of the application flow
		service,                   //service of the application flow, can be set to ""
		ipresolution,              //IP resolution of the remote IP, can be set to ""
		maxDistance,               //maximum distance to reach
		numberIterations,          //number of probes per hop
		timeout,                   //timeout to wait before considering a probe lost [ms]
		flowTimeout,               //idletime to wait before considering dead the application flow
		interProbeTime,            //gap of time between each pair of probe [us]
		interIterationTime,        //gap of time between each pair of iterations (different TTL) [us]
		probingAlgorithm,          //probing algorithm to use: PacketByPacket (1 packet at a time), HopByHop (all packets for one hop at a time) and Concurrent, all probes at once
		stopWithBorderRouters,     //stop the traceroute when a border router is detected. Not working with Concurrent algorithm
		startWithEmptyPacket,      //whether to start traceroute when a packet is detected or when a packet WITH payload is detected
		maxConsecutiveMissingHops, //maximum number of consecutive non replying hops before considering the path fully discovered. 0 means infinity
	)

	//Start ServiceTracerouteManager listener in order to manage all incoming and outgoing packets
	//If services are added, ST automatically starts traceroute to them when new application flows are detected
	go traceTCPManager.Run()

	//Run() is a blocking function, therefore to keep the thread free, it is required to run it through go
	//However, then if the main closes, the tool closes too
	//This is a small portion of code to keep alive the tool
	//It kills the tool after 10 minutes
	//However it can be closed in other ways, like after an idle time or calling the Stop() function

	start := time.Now().UnixNano()
	maxLifeTime := 600
	for {
		now := time.Now().UnixNano()

		if maxLifeTime > 0 && (time.Duration(now-start) > time.Duration(maxLifeTime)*time.Second) {
			fmt.Println("Maximum lifetime reached")
			break
		}
		time.Sleep(5 * time.Second)
	}
}
