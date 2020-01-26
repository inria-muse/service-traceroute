package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/inria-muse/service-traceroute/pkg/servicetraceroute"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func checkFlags(version bool, iface string, services arrayFlags, hosts arrayFlags, distance int, iterations int, timeout int, interProbeTime int, interIterationTime int, probingAlgorithm string, maxMissingHops int) {
	if version {
		fmt.Printf("%s\n", servicetraceroute.Version)
		os.Exit(0)
	}

	if iface == "" {
		panic("Interface not valid")
	}

	if distance <= 0 {
		panic("Not valid distance")
	}

	if iterations <= 0 {
		panic("Not valid number of iterations")
	}

	if timeout < 0 {
		panic("Negative timeout")
	}

	if maxMissingHops < 0 {
		panic("Negative maximum number of consecutive hops")
	}

	if interProbeTime < 0 {
		panic("Negative inter probe time")
	}

	if interIterationTime < 0 {
		panic("Negative inter iteration time")
	}

	if strings.ToLower(probingAlgorithm) != servicetraceroute.PacketByPacket && strings.ToLower(probingAlgorithm) != servicetraceroute.HopByHop && strings.ToLower(probingAlgorithm) != servicetraceroute.Concurrent {
		panic("Wrong probing algorithm")
	}

	if len(services) <= 0 && len(hosts) <= 0 {
		panic("No destination set. Use --services or --hosts to define the service or host to trace")
	}
}

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

func main() {
	var version bool
	flag.BoolVar(&version, "version", false, "Print version and exit")

	var iface string
	flag.StringVar(&iface, "iface", "", "Interface to use")

	var ipVersion string
	flag.StringVar(&ipVersion, "ipversion", servicetraceroute.V4, "Version of IP protocol. Now only IPv4 is supported")

	var services arrayFlags
	flag.Var(&services, "services", "Services to probe")

	var hosts arrayFlags
	flag.Var(&hosts, "hosts", "Hosts to probe")

	var borderRouters arrayFlags
	flag.Var(&hosts, "borders", "IP addresses where Service Traceroute must stop probing")

	var interTraceTime int
	flag.IntVar(&interTraceTime, "intertracetime", 600, "Time [s] between 2 Traceroute using the same flow ID (i.e. the same Traceroutes). Negative values means infinite time")

	var emptyPacket bool
	flag.BoolVar(&emptyPacket, "empty", true, "Specify whether Service Traceroute can start when it detects an outgoing empty packet of the target application flow")

	var sameDestination bool
	flag.BoolVar(&sameDestination, "samehost", true, "Specify whether Service Traceroute can start multiple traceroutes to the same destination but with different destination ports")

	var samePort bool
	flag.BoolVar(&samePort, "sameport", true, "Specify whether Service Traceroute can start multiple traceroutes to the same destination and destination ports")

	var distance int
	flag.IntVar(&distance, "distance", 8, "Maximum distance")

	var iterations int
	flag.IntVar(&iterations, "iterations", 3, "Number of packets per hop")

	var timeout int
	flag.IntVar(&timeout, "timeout", 2000, "Timeout [ms] to wait for replies")

	var flowTimeout int
	flag.IntVar(&flowTimeout, "flowtimeout", 0, "Timeout [ms] to consider a flow dead when no packets are exchanged. 0 or negative values means infinite ")

	var interProbeTime int
	flag.IntVar(&interProbeTime, "ipt", 20000, "Inter probe time [us]: time between each pair of probe")

	var interIterationTime int
	flag.IntVar(&interIterationTime, "itt", 1000, "Inter iteration time [us]: time between each train of probes (same TTL)")

	var probingAlgorithm string
	flag.StringVar(&probingAlgorithm, "algorithm", "PacketByPacket", "Probing algorithm. 'PacketByPacket' - One packet and wait, 'HopByHop' - One train of packets and wait, 'Concurrent' - All packets and wait")

	var startTraceroutes bool
	flag.BoolVar(&startTraceroutes, "start", true, "Specify whether Service Traceroute has to start the probing phase or not (DEBUGGING).")

	var tracetcpTimeout int
	flag.IntVar(&tracetcpTimeout, "idle", 0, "Timeout [s] to wait to close Service Traceroute when there are no traceroute running in the background. 0 or negative values means infinite")

	var maxLifeTime int
	flag.IntVar(&maxLifeTime, "lifetime", 0, "Maximum lifetime [s] of tracetcp. 0 or negative values means infinite")

	var output string
	flag.StringVar(&output, "output", "traceroute", "How results are showed: 'traceroute' (default) or 'json'.")

	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "Show error messages")

	var dns bool
	flag.BoolVar(&dns, "dns", true, "DNS listener")

	var maxMissingHops int
	flag.IntVar(&maxMissingHops, "max-stars", 3, "Maximum number of non replying hops before ending a traceroute. Standard is 3")

	var stopAfter int
	flag.IntVar(&stopAfter, "stop", 0, "Specify if ServiceTraceroute has to stop new analysis after a specific interval [s]. 0 or negatives means do not stop")

	flag.Parse()

	//Check if input arguments are fine
	checkFlags(version, iface, services, hosts, distance, iterations, timeout, interProbeTime, interIterationTime, probingAlgorithm, maxMissingHops)

	outChan := make(chan string, 1000)
	reportChan := make(chan servicetraceroute.ServiceTracerouteJson, 100)

	//Start the thread receiving the results and messages from the library
	go traceOut(outChan, reportChan, output)

	//Parse the border routers given in input from the command line
	borderIPs := make([]net.IP, 0)
	for _, v := range borderRouters {
		if ip, _, err := net.ParseCIDR(v); err == nil {
			borderIPs = append(borderIPs, ip)
		}
	}

	urls := make([]string, 0)
	ips := make([]string, 0)

	//Parse the input hosts and split them between IPs and URLs
	for _, host := range hosts {
		if _, _, err := net.ParseCIDR(host); err == nil {
			ips = append(ips, host)
		} else {
			urls = append(urls, host)
		}
	}

	//Initialize traceTCP Manager
	traceTCPManager := new(servicetraceroute.ServiceTracerouteManager)

	//Set all parameters
	traceTCPManager.NewServiceTracerouteManager(iface, ipVersion, sameDestination, samePort, true, true, dns, startTraceroutes, interTraceTime, maxMissingHops, borderIPs, outChan, reportChan)
	//Only to show errors
	traceTCPManager.SetVerbose(verbose)

	//Add services to traceroute
	//Services are online application that can be analyzed automatically without giving urls and ips
	//In case a service is not yet available, it can be added easily with this function.
	//This is done for IPs and URLs, a service is created for each url and all IPs.
	//It is just enough to specify the name and URLs and IPs matching a specific online service
	for _, service := range services {
		traceTCPManager.AddService(servicetraceroute.ServiceConfiguration{
			ConfHash:             "",
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

	//Add urls to analyze
	//These urls are seen as under a service with the same name as the given url
	for _, url := range urls {
		traceTCPManager.AddService(servicetraceroute.ServiceConfiguration{
			ConfHash:             "",
			Distance:             distance,
			InterIterationTime:   interIterationTime,
			InterProbeTime:       interProbeTime,
			Iterations:           iterations,
			ProbingAlgorithm:     probingAlgorithm,
			Service:              url,
			URLs:                 []string{url},
			IPPrefixes:           ips,
			StartWithEmptyPacket: emptyPacket,
			Timeout:              timeout,
			FlowTimeout:          flowTimeout,
		})
	}

	//Same for urls but for IPs
	//In this case, the service is called IPs
	traceTCPManager.AddService(servicetraceroute.ServiceConfiguration{
		ConfHash:             "",
		Distance:             distance,
		InterIterationTime:   interIterationTime,
		InterProbeTime:       interProbeTime,
		Iterations:           iterations,
		ProbingAlgorithm:     probingAlgorithm,
		Service:              "IPs",
		URLs:                 urls,
		IPPrefixes:           ips,
		StartWithEmptyPacket: emptyPacket,
		Timeout:              timeout,
		FlowTimeout:          flowTimeout,
	})

	//Run the listener
	go traceTCPManager.Run()

	//The next line of codes are used only for the standalone tool to manage the lifecycle of the standalone tool
	//The tool can stop in 2 different ways:
	// - Maximum lifetime: it is possible to say how long this tool can run and after this amount of time, close.
	// - Maximum idle time: it is possible to say to the tool to stop after an interval of time where no packets of the target services are exchanged
	//Moreover it is possible to stop the traceroute after an interval of time from the start.

	//Management of the standalone tool
	//It only checks the idle time (if >0), maximum lifetime (if >0) and the possibility to stop new traceroutes
	outChan <- fmt.Sprintf("Starting ServiceTraceroute of %d in an idle state", tracetcpTimeout)
	start := time.Now().UnixNano()
	beginning := time.Now().UnixNano()
	stopped := false
	for {
		now := time.Now().UnixNano()
		if traceTCPManager.GetNumberOfRunningServiceTraceroute() > 0 {
			beginning = time.Now().UnixNano()
		}

		//If maximum idle time is reached, exit
		if time.Duration(now-beginning) > (time.Duration(tracetcpTimeout)*time.Second) && tracetcpTimeout > 0 {
			fmt.Println("Maximum idle time reached")
			break
		}

		//If maximum lifetime is reached, exit
		if maxLifeTime > 0 && (time.Duration(now-start) > time.Duration(maxLifeTime)*time.Second) {
			fmt.Println("Maximum lifetime reached")
			break
		}
		//Do not create new traceroute after an interval of time (if >0)
		if stopAfter > 0 && (time.Duration(now-start) > time.Duration(stopAfter)*time.Second && !stopped) {
			traceTCPManager.SetStartNewTraceroutes(false)
			fmt.Println("Stopping new traceroutes")
			stopped = true
		}
		time.Sleep(5 * time.Second)
	}
}
