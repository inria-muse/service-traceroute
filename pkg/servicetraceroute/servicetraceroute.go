package servicetraceroute

import (
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
)

//Version of Service Traceroute
const (
	Version = "0.3d" // MAKE SURE TO INCREMENT AFTER EVERY CHANGE
)

//Available probing algorithms
const (
	PacketByPacket = "packetbypacket" //Send one packet and then wait the reply
	HopByHop       = "hopbyhop"       //Send all the packets with the same TTL and then wait the replies
	Concurrent     = "concurrent"     //Send all packets at once and then wait the replies (one timeout)
)

//IP Versions and protocols
const (
	V4   = "4"
	V6   = "6"
	Tcp  = "tcp"
	Icmp = "icmp"
	Udp  = "udp"
	Dns  = "dns"
)

//Default values for the a new traceroute
const (
	DefaultIterations                = 10
	DefaultDistance                  = 32
	DefaultInterProbeTime            = 20  //ms
	DefaultInterIterationTime        = 100 // ms
	DefaultProbingAlgorithm          = PacketByPacket
	DefaultWaitProbe                 = false
	DefaultTimeout                   = 2000 //ms
	DefaultMaxConsecutiveMissingHops = 3
)

//Structure with main information for the capturing class
type CapThread struct {
	BPF     string
	Buffer  int
	CapSize int
	Port    uint16
	IP      string
}

//Main structure of the Json output
//Info - contains the info about the tool
//Data - contains all the data about the traceroute
type ServiceTracerouteJson struct {
	Info ServiceTracerouteInfo
	Data ServiceTracerouteReport
}

//One part of the Json output
//Version - the version of the tool
//Conf - a string that can be associated to a specific traceroute
//Type - the tool which generated the output
type ServiceTracerouteInfo struct {
	Version string
	Conf    string
	Type    string
}

//Contains all information and results about traceroute
type ServiceTracerouteReport struct {
	TransportProtocol string    //Transport protocol that was used during the traceroute. UDP or TCP
	TargetIP          string    //The target IP to reach
	TargetPort        int       //The port of the target IP appartaining at the target application flow
	LocalIP           string    //IP of the host running the traceroute
	LocalPort         int       //Port of the host appartaining at target application flow
	Service           string    //Name of the service
	IPResolution      string    //Corresponding resolution name used to detect the application flow
	Hops              []string  //IP for each hop
	RttsAvg           []float64 //RTT AVG for each hop
	RttsVar           []float64 //RTT VAR for each hop (if >1 iterations)

	MaxTtl         int //Maximum TTL to reach
	BorderDistance int //Distance reached by the tool during the probing phase. It depends on border routers, lifetime of the application flow or when there are consecutive non replying hops
	Iterations     int //Number of probes per hop

	MaxConsecutiveMissingHops        int  //Maximum number of consecutive non replying hops before considering the flow and completed
	ReachedMaxConsecutiveMissingHops bool //Flag to specify if the traceroute was stopped by the maximum number of consecutive non replying hops

	ProbingAlgorithm     string //The type of probing algorithm used during the traceroute
	StartWithEmptyPacket bool   //Whether Service Traceroute can start when it detects an empty packet or a packet with transport payload

	InterProbeTime     int //Time between each probe in [us]
	InterIterationTime int //Time between each iteration of TTL [us]

	Timeout            int  //The maximum time to wait before considering a packet as lost
	FlowTimeout        int  //The maximum idle time to consider a flow as dead
	ReachedFlowTimeout bool //Flag to specify if the application flow is considered dead due to inactivity (in case no RST or FIN packets are exchanged)
	FlowEnded          bool //Flag to specify if the application flow was closed with RST or FIN

	ReachedBorderRouter bool //Flag to specify if Service Traceroute reached a border router

	TsStart int64 //Timestamp of the start of the traceroute
	TsEnd   int64 //Timestamp of the end of the traceroute

	HopIPs [][]string  //Full list of received IPs
	Rtts   [][]float64 //Full list of RTTs
}

type ServiceConfiguration struct {
	Service              string //Name of the service. If existing the input.conf, it can be used without IPs or URLs to identify automatically a specific service
	ServiceType          uint8  //Id of the service type.
	ConfHash             string //Set externally to identify the results
	Distance             int    //Maximum distance to probe
	Iterations           int    //Number of packets per hop
	InterProbeTime       int    //Time to wait between each probe
	InterIterationTime   int    //Time to wait between each iteration
	Timeout              int    //Timeout (milliseconds)
	FlowTimeout          int    //Timeout to consider a flow dead (milliseconds)
	ProbingAlgorithm     string //Spacify the probing algorithm to use. 0 to send 1 packet at the time. 1 to send 1 train of packet (same TTL) at the time. 2 to send all packets without waiting for the reply, only to wait the timeout at the end. If different, 0 will be used as default
	StartWithEmptyPacket bool   //Flag to specify whether ServiceTraceroute has to start when an empty ack is received. ServiceTraceroute always starts with ACK with payload
	StopOnBorderRouters  bool   //Flag to specify to stop when Service Traceroute detects a border router

	IPPrefixes []string //IP Prefixes appartaining to the service
	URLs       []string //URLs appartaining to the service
}

//Configuration to run ServiceTraceroute
type ServiceTracerouteConfiguration struct {
	TransportProtocol         string   //Type of protocol to probe. UDP or TCP
	ConfHash                  string   //Hash to identify a specific traceroute. Given externally by who uses the library
	Service                   string   //Type of service of the remote IP
	IPResolution              string   //Resolution name of the remote IP
	LocalIPv4                 net.IP   //IPv4 of the local machine
	LocalIPv6                 net.IP   //IPv6 of the local machine
	RemoteIP                  net.IP   //IP of the remote target end host
	RemotePort                int      //Port of the remote target end host
	LocalPort                 int      //Port of the local end host
	Interface                 string   //Interface used to transmit packets
	Distance                  int      //Max TTL to reach (from 1 to Distance included ?)
	BorderIPs                 []net.IP //Set of IPs that, if encountered, will stop ServiceTraceroute
	Iterations                int      //Number of probes for each TTL
	InterProbeTime            int      //Time to wait between each probe
	InterIterationTime        int      //Time to wait between each iteration
	IPVersion                 string   //IP Version
	Timeout                   int      //Timeout (milliseconds)
	IDOffset                  uint16   //Offset for the IP ID field in order to allow parallelisation without interference with running ServiceTraceroutes
	ProbingAlgorithm          string   //Spacify the probing algorithm to use. 0 to send 1 packet at the time. 1 to send 1 train of packet (same TTL) at the time. 2 to send all packets without waiting for the reply, only to wait the timeout at the end. If different, 0 will be used as default
	StartWithEmptyPacket      bool     //Flag to specify whether ServiceTraceroute has to start when an empty ack is received. ServiceTraceroute always starts with ACK with payload
	FlowTimeout               int      //Time required to consider a flow dead
	MaxConsecutiveMissingHops int      //Set how many missing hops (stars *) are required before ending traceroute

	StartTraceroutes bool //Debug, stop immediately the traceroute
}

//Struct which contains the required objects to run ServiceTraceroute
//This struct is associated to only one traceroute
type ServiceTraceroute struct {
	//The input configuration of Service Traceroute
	Configuration ServiceTracerouteConfiguration
	//Receiver and analyser of the input packets
	Receiver   *Receiver
	Traceroute *BufferTrace

	//Queue containing the sniffed pacets
	SniffChannel chan *gopacket.Packet

	//Messages to be printed/stored
	OutChan chan string

	//Packets to be transmitted
	OutPacketsChan chan []byte

	//Notify when it finishes
	DoneChan chan bool
}

//Start Service Traceroute with default parameters
func (tt *ServiceTraceroute) NewDefaultServiceTraceroute(transportProtocol string, remoteIP net.IP, localIPv4 net.IP, localIPv6 net.IP, remotePort int, iface string, outchan chan string) {
	tt.Configuration.TransportProtocol = transportProtocol
	tt.SetLocalIPv4(localIPv4)
	tt.SetLocalIPv6(localIPv6)
	tt.SetRemoteIP(remoteIP)
	tt.SetRemotePort(remotePort)
	tt.SetInterface(iface)
	tt.SetStdOutChan(outchan)
	tt.Configuration.MaxConsecutiveMissingHops = 3

	//Default Configuration
	tt.SetIterations(DefaultIterations)
	tt.SetDistance(DefaultDistance)
	tt.SetInterIterationTime(DefaultInterIterationTime)
	tt.SetInterProbeTime(DefaultInterProbeTime)
	tt.SetIPv4()
	tt.SetProbingAlgorithm(DefaultProbingAlgorithm)
	tt.SetTimeout(DefaultTimeout)
	tt.SetProbingAlgorithm(DefaultProbingAlgorithm)
	tt.SniffChannel = make(chan *gopacket.Packet, 1000)
}

//Start Service Traceroute with the given configuration
//If the given configuration contains the wrong probing algorithm, the Service Traceroute use PacketByPacket as default algorithm
func (tt *ServiceTraceroute) NewConfiguredServiceTraceroute(configuration ServiceTracerouteConfiguration) {
	tt.Configuration = configuration
	tt.SniffChannel = make(chan *gopacket.Packet, 1000)
	tt.Configuration.ProbingAlgorithm = strings.ToLower(tt.Configuration.ProbingAlgorithm)

	if tt.Configuration.ProbingAlgorithm != HopByHop && tt.Configuration.ProbingAlgorithm != Concurrent {
		tt.Configuration.ProbingAlgorithm = PacketByPacket
	}
}

//Start a traceroute towards for a specific application flow given during the initialization of the object
func (tt *ServiceTraceroute) Run() ServiceTracerouteJson {
	start := time.Now().UnixNano() / int64(time.Millisecond)

	//Start receiver asynchronously
	tt.Receiver = new(Receiver)
	tt.Receiver.NewReceiver(tt.SniffChannel, tt.Configuration.StartWithEmptyPacket, tt.Configuration.LocalIPv4, tt.Configuration.LocalIPv6, tt.OutChan)
	go tt.Receiver.Run()

	outPktChan := tt.OutPacketsChan

	//Start buffertrace (main core of traceroute) synchronously
	tt.Traceroute = new(BufferTrace)
	tt.Traceroute.MaxTtl = tt.Configuration.Distance
	tt.Traceroute.NewBufferTrace(
		tt.Configuration.TransportProtocol,
		tt.Configuration.IPVersion,
		tt.Receiver,
		tt.Configuration.Distance-1,
		tt.Configuration.Iterations,
		tt.Configuration.InterProbeTime,
		tt.Configuration.InterIterationTime,
		tt.Configuration.Timeout,
		tt.Configuration.IDOffset,
		tt.Configuration.ProbingAlgorithm,
		tt.Configuration.FlowTimeout,
		tt.Configuration.StartTraceroutes,
		tt.Configuration.MaxConsecutiveMissingHops,
		tt.Configuration.BorderIPs,
		outPktChan,
		tt.OutChan,
	)

	//Start buffertrace (traceroute) and get the report
	report := tt.Traceroute.Run()

	//Close and wait the receiver
	tt.Receiver.Stop()
	<-tt.Receiver.DoneChan

	end := time.Now().UnixNano() / int64(time.Millisecond)

	//store more details in the report and return it
	report.Service = tt.Configuration.Service
	report.IPResolution = tt.Configuration.IPResolution
	report.StartWithEmptyPacket = tt.Configuration.StartWithEmptyPacket
	report.TargetIP = tt.Configuration.RemoteIP.String()
	report.TargetPort = tt.Configuration.RemotePort
	if tt.Configuration.IPVersion == V4 {
		report.LocalIP = tt.Configuration.LocalIPv4.String()
	} else {
		report.LocalIP = tt.Configuration.LocalIPv6.String()
	}
	report.LocalPort = int(tt.Receiver.Curr.LocalPort)
	report.TsStart = start
	report.TsEnd = end

	reportInfo := ServiceTracerouteInfo{
		Version: Version,
		Type:    "ServiceTraceroute",
		Conf:    tt.Configuration.ConfHash,
	}

	completeReport := ServiceTracerouteJson{
		Info: reportInfo,
		Data: report,
	}

	return completeReport
}

/*************** Get&Set ***************/

//Set the IPv4 of the machine running Service Traceroute
func (tt *ServiceTraceroute) SetLocalIPv4(localIPv4 net.IP) {
	tt.Configuration.LocalIPv4 = localIPv4
}

//Set the IPv6 of the machine running Service Traceroute
func (tt *ServiceTraceroute) SetLocalIPv6(localIPv6 net.IP) {
	tt.Configuration.LocalIPv6 = localIPv6
}

//Set the IPv4 of the other end host of a specific application flow
func (tt *ServiceTraceroute) SetRemoteIP(remoteIP net.IP) {
	tt.Configuration.RemoteIP = remoteIP
}

//Set the port of the other end host of a specific application flow
func (tt *ServiceTraceroute) SetRemotePort(remotePort int) {
	tt.Configuration.RemotePort = remotePort
}

//Set the port of the the machine running Service Traceroute of a specific application flow
func (tt *ServiceTraceroute) SetLocalPort(localPort int) {
	tt.Configuration.LocalPort = localPort
}

//Set the interface to use of the machine running Service Traceroute
func (tt *ServiceTraceroute) SetInterface(iface string) {
	tt.Configuration.Interface = iface
}

//Set the maximum distance to probe
func (tt *ServiceTraceroute) SetDistance(distance int) {
	tt.Configuration.Distance = distance
}

//Get the maximum distance to probe
func (tt *ServiceTraceroute) GetDistance() int {
	return tt.Configuration.Distance
}

//Set the border routers for a specific traceroute
func (tt *ServiceTraceroute) SetBorderIPs(borderIPs []net.IP) {
	tt.Configuration.BorderIPs = borderIPs
}

//Set the number of probes per TTL
func (tt *ServiceTraceroute) SetIterations(iterations int) {
	tt.Configuration.Iterations = iterations
}

//Get the number of probes per TTL
func (tt *ServiceTraceroute) GetIterations() int {
	return tt.Configuration.Iterations
}

//Set the time to wait between each pair of probe [us]
func (tt *ServiceTraceroute) SetInterProbeTime(interProbeTime int) {
	tt.Configuration.InterProbeTime = interProbeTime
}

//Set the time to wait between each pair of TTL [us]
func (tt *ServiceTraceroute) SetInterIterationTime(interIterationTime int) {
	tt.Configuration.InterIterationTime = interIterationTime
}

//Set the IP version to 4
func (tt *ServiceTraceroute) SetIPv4() {
	tt.Configuration.IPVersion = V4
}

//Set the IP version to 6 (it is not fully implemented)
func (tt *ServiceTraceroute) SetIPv6() {
	tt.Configuration.IPVersion = V6
}

//Set the timeout for considering a probe lost [ms]
func (tt *ServiceTraceroute) SetTimeout(timeout int) {
	tt.Configuration.Timeout = timeout
}

//Set the idle time to consider a flow as closed [ms]
func (tt *ServiceTraceroute) SetFlowTimeout(timeout int) {
	tt.Configuration.FlowTimeout = timeout
}

//Set the channel for the standard output
func (tt *ServiceTraceroute) SetStdOutChan(outchan chan string) {
	tt.OutChan = outchan
}

//Set the channel for the packets to be transmitted
func (tt *ServiceTraceroute) SetOutPacketsChan(outPacketsChan chan []byte) {
	tt.OutPacketsChan = outPacketsChan
}

//Set the IPID offset (to enable multiple traceroutes)
func (tt *ServiceTraceroute) SetIDOffset(idOffset uint16) {
	tt.Configuration.IDOffset = idOffset
}

//Get the IPID offset
func (tt *ServiceTraceroute) GetIDOffset() uint16 {
	return tt.Configuration.IDOffset
}

//Set the probing algorithm
func (tt *ServiceTraceroute) SetProbingAlgorithm(probingAlgorithm string) {
	tt.Configuration.ProbingAlgorithm = probingAlgorithm
}

//Get the probing algorithm
func (tt *ServiceTraceroute) GetProbingAlgorithm() string {
	return tt.Configuration.ProbingAlgorithm
}

//Set the service associated to this traceroute
func (tt *ServiceTraceroute) SetService(service string) {
	tt.Configuration.Service = service
}

//Set whether the traceroute should start only when data is exchanged (=packets with payload) or also with empty packets
func (tt *ServiceTraceroute) SetStartWithEmptyPacket(start bool) {
	tt.Configuration.StartWithEmptyPacket = start
}
