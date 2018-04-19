package main

import (
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
)

const (
	V4   = "4"
	V6   = "6"
	Tcp  = "tcp"
	Icmp = "icmp"
	Udp  = "udp"
)

const (
	DefaultIterations         = 10
	DefaultDistance           = 32
	DefaultInterProbeTime     = 20  //ms
	DefaultInterIterationTime = 100 // ms
	DefaultSniffingFlag       = true
	DefaultSendPacketsFlag    = true
	DefaultWaitProbe          = false
	DefaultTimeout            = 2000 //ms
)

type CapThread struct {
	BPF     string
	Buffer  int
	CapSize int
}

//Used if Sniffing is TRUE
var TCPCapThread = CapThread{BPF: Tcp, Buffer: 10000, CapSize: 100}
var ICMPCapThread = CapThread{BPF: Icmp, Buffer: 10000, CapSize: 100}

type TraceTCPJson struct {
	Info TraceTCPInfo
	Data TraceTCPReport
}

type TraceTCPInfo struct {
	Version string
	Conf    string
	Type    string
}

type TraceTCPReport struct {
	TargetIP   string
	TargetPort int
	LocalIP    string
	LocalPort  int
	Service    string
	Hops       []string  //IP for each hop
	RttsAvg    []float64 //RTT AVG for each hop
	RttsVar    []float64 //RTT VAR for each hop (if >1 iterations)

	MaxTtl         int
	BorderDistance int
	Iterations     int

	InterProbeTime     int
	InterIterationTime int

	ReachedBorderRouter bool

	TsStart int64
	TsEnd   int64
}

//Configuration to run TraceTCP
type TraceTCPConfiguration struct {
	ConfHash             string
	Service              string   //Type of service of the remote IP
	LocalIPv4            net.IP   //IPv4 of the local machine
	LocalIPv6            net.IP   //IPv6 of the local machine
	RemoteIP             net.IP   //IP of the remote target end host
	RemotePort           int      //Port of the remote target end host
	LocalPort            int      //Port of the local end host
	Interface            string   //Interface used to transmit packets
	Distance             int      //Max TTL to reach (from 1 to Distance included ?)
	BorderIPs            []net.IP //Set of IPs that, if encountered, will stop TraceTCP
	Iterations           int      //Number of probes for each TTL
	InterProbeTime       int      //Time to wait between each probe
	InterIterationTime   int      //Time to wait between each iteration
	IPVersion            string   //IP Version
	Sniffing             bool     //Specify if TraceTCP has to sniff on the interface or receive packets through the APIs
	CanSendPackets       bool     //Specify if TraceTCP will send packets autonomously or delegate it to someone else
	Timeout              int      //Timeout (milliseconds)
	IDOffset             uint16   //Offset for the IP ID field in order to allow parallelisation without interference with running TraceTCPs
	WaitProbe            bool     //Flag to specify if it is required to wait the reply for each transmitted probe (send - wait - analyse). If false, then TraceTCP will wait for the train
	StartWithEmptyPacket bool     //Flag to specify whether TraceTCP has to start when an empty ack is received. TraceTCP always starts with ACK with payload
}

//Struct to contains required objects to run TraceTCP
type TraceTCP struct {
	Configuration TraceTCPConfiguration
	Sender        *Sender
	Receiver      *Receiver
	Traceroute    *BufferTrace

	//Used if Sniffing==True
	SniffTCPHandler  *PcapHandler
	SniffICMPHandler *PcapHandler

	//Used it Sniffing==False
	SniffChannel chan *gopacket.Packet

	//Messages to be printed/stored
	OutChan chan string

	//Packets to be transmitted
	OutPacketsChan chan []gopacket.SerializableLayer

	//Notify when it finishes
	DoneChan chan bool
}

func (tt *TraceTCP) NewDefaultTraceTCP(remoteIP net.IP, localIPv4 net.IP, localIPv6 net.IP, remotePort int, iface string, outchan chan string) {
	tt.SetLocalIPv4(localIPv4)
	tt.SetLocalIPv6(localIPv6)
	tt.SetRemoteIP(remoteIP)
	tt.SetRemotePort(remotePort)
	tt.SetInterface(iface)
	tt.SetStdOutChan(outchan)

	//Default Configuration
	tt.SetIterations(DefaultIterations)
	tt.SetDistance(DefaultDistance)
	tt.SetInterIterationTime(DefaultInterIterationTime)
	tt.SetInterProbeTime(DefaultInterProbeTime)
	tt.SetIPv4()
	tt.SetSniffingFlag(DefaultSniffingFlag)
	tt.SetSendPacketsFlag(DefaultSendPacketsFlag)
	tt.SetTimeout(DefaultTimeout)
	tt.SetWaitProbeFlag(DefaultWaitProbe)
	tt.SniffChannel = make(chan *gopacket.Packet, 1000)
}

func (tt *TraceTCP) NewConfiguredTraceTCP(configuration TraceTCPConfiguration) {
	tt.Configuration = configuration
	tt.SniffChannel = make(chan *gopacket.Packet, 1000)
}

func (tt *TraceTCP) Run() TraceTCPJson {
	//Init channels
	ready := make(chan bool)

	start := time.Now().UnixNano() / int64(time.Millisecond)

	//Define PcapHandler based on sniffing flag
	if tt.Configuration.Sniffing {
		//Start PCAP Handler
		tt.SniffTCPHandler = new(PcapHandler)
		tt.SniffICMPHandler = new(PcapHandler)

		tt.SniffTCPHandler.NewPacketHandler(TCPCapThread, tt.Configuration.Interface, tt.Configuration.IPVersion, tt.Configuration.RemoteIP.String(), tt.Configuration.RemotePort, tt.SniffChannel, tt.OutChan, ready)
		tt.SniffICMPHandler.NewPacketHandler(ICMPCapThread, tt.Configuration.Interface, tt.Configuration.IPVersion, tt.Configuration.RemoteIP.String(), tt.Configuration.RemotePort, tt.SniffChannel, tt.OutChan, ready)

		//Start and wait that it is ready
		go tt.SniffTCPHandler.Run()
		<-ready

		//Start and wait that it is ready
		go tt.SniffICMPHandler.Run()
		<-ready
	}

	//Start receiver asynchronously
	tt.Receiver = new(Receiver)
	tt.Receiver.NewReceiver(tt.SniffChannel, tt.Configuration.StartWithEmptyPacket, tt.Configuration.LocalIPv4, tt.Configuration.LocalIPv6, tt.OutChan)
	go tt.Receiver.Run()

	var outPktChan chan []gopacket.SerializableLayer

	//If TraceTCP has to forward outgoing packets (and it is correctly configured)
	//Then do not start sender, just redirect packets on the correct channel
	//Otherwise, start Sender and use its queue
	if !tt.Configuration.CanSendPackets && tt.OutPacketsChan != nil {
		outPktChan = tt.OutPacketsChan
	} else {
		//Start sender asynchronously
		tt.Sender = new(Sender)
		tt.Sender.NewSender(tt.Configuration.Interface, tt.Receiver, tt.OutChan)
		go tt.Sender.Run()

		outPktChan = tt.Sender.SendQ
	}

	//Start buffertrace synchronously
	tt.Traceroute = new(BufferTrace)
	tt.Traceroute.MaxTtl = tt.Configuration.Distance
	tt.Traceroute.NewBufferTrace(tt.Receiver,
		tt.Configuration.Distance-1,
		tt.Configuration.Iterations,
		tt.Configuration.InterProbeTime,
		tt.Configuration.InterIterationTime,
		tt.Configuration.Timeout,
		tt.Configuration.IDOffset,
		tt.Configuration.WaitProbe,
		tt.Configuration.BorderIPs,
		outPktChan,
		tt.OutChan,
	)

	report := tt.Traceroute.Run()

	//Close everything and wait to synch with the thread
	if tt.SniffTCPHandler != nil {
		tt.SniffTCPHandler.Stop()
		<-tt.SniffTCPHandler.DoneChan
	}

	if tt.SniffICMPHandler != nil {
		tt.SniffICMPHandler.Stop()
		<-tt.SniffICMPHandler.DoneChan
	}

	tt.Receiver.Stop()
	<-tt.Receiver.DoneChan

	if tt.Sender != nil {
		tt.Sender.Stop()
		<-tt.Sender.DoneChan
	}

	end := time.Now().UnixNano() / int64(time.Millisecond)

	//send report
	report.Service = tt.Configuration.Service
	report.TargetIP = tt.Configuration.RemoteIP.String()
	report.TargetPort = tt.Configuration.RemotePort
	if tt.Configuration.IPVersion == V4 {
		report.LocalIP = tt.Configuration.LocalIPv4.String()
	} else {
		report.LocalIP = tt.Configuration.LocalIPv6.String()
	}
	report.LocalPort, _ = strconv.Atoi(tt.Receiver.Curr.LocalPort.String())
	report.TsStart = start
	report.TsEnd = end

	reportInfo := TraceTCPInfo{
		Version: Version,
		Type:    "TraceTCP",
		Conf:    tt.Configuration.ConfHash,
	}

	completeReport := TraceTCPJson{
		Info: reportInfo,
		Data: report,
	}

	out, _ := json.Marshal(completeReport)

	tt.OutChan <- string(out) + "\n"

	return completeReport
}

func (tt *TraceTCP) InsertTCPPacket(pkt *gopacket.Packet) {
	tt.SniffChannel <- pkt
}

func (tt *TraceTCP) InsertICMPChannel(pkt *gopacket.Packet) {
	tt.SniffChannel <- pkt
}

func (tt *TraceTCP) SetLocalIPv4(localIPv4 net.IP) {
	tt.Configuration.LocalIPv4 = localIPv4
}

func (tt *TraceTCP) SetLocalIPv6(localIPv6 net.IP) {
	tt.Configuration.LocalIPv6 = localIPv6
}

func (tt *TraceTCP) SetRemoteIP(remoteIP net.IP) {
	tt.Configuration.RemoteIP = remoteIP
}

func (tt *TraceTCP) SetRemotePort(remotePort int) {
	tt.Configuration.RemotePort = remotePort
}

func (tt *TraceTCP) SetLocalPort(localPort int) {
	tt.Configuration.LocalPort = localPort
}

func (tt *TraceTCP) SetInterface(iface string) {
	tt.Configuration.Interface = iface
}

func (tt *TraceTCP) SetDistance(distance int) {
	tt.Configuration.Distance = distance
}

func (tt *TraceTCP) GetDistance() int {
	return tt.Configuration.Distance
}

func (tt *TraceTCP) SetBorderIPs(borderIPs []net.IP) {
	tt.Configuration.BorderIPs = borderIPs
}

func (tt *TraceTCP) SetIterations(iterations int) {
	tt.Configuration.Iterations = iterations
}

func (tt *TraceTCP) GetIterations() int {
	return tt.Configuration.Iterations
}

func (tt *TraceTCP) SetInterProbeTime(interProbeTime int) {
	tt.Configuration.InterProbeTime = interProbeTime
}

func (tt *TraceTCP) SetInterIterationTime(interIterationTime int) {
	tt.Configuration.InterIterationTime = interIterationTime
}

func (tt *TraceTCP) SetIPv4() {
	tt.Configuration.IPVersion = V4
}

func (tt *TraceTCP) SetIPv6() {
	tt.Configuration.IPVersion = V6
}

func (tt *TraceTCP) SetSniffingFlag(sniffing bool) {
	tt.Configuration.Sniffing = sniffing
}

func (tt *TraceTCP) SetSendPacketsFlag(canSendPackets bool) {
	tt.Configuration.CanSendPackets = canSendPackets
}

func (tt *TraceTCP) SetTimeout(timeout int) {
	tt.Configuration.Timeout = timeout
}

func (tt *TraceTCP) SetStdOutChan(outchan chan string) {
	tt.OutChan = outchan
}

func (tt *TraceTCP) SetOutPacketsChan(outPacketsChan chan []gopacket.SerializableLayer) {
	tt.OutPacketsChan = outPacketsChan
}

func (tt *TraceTCP) SetIDOffset(idOffset uint16) {
	tt.Configuration.IDOffset = idOffset
}

func (tt *TraceTCP) GetIDOffset() uint16 {
	return tt.Configuration.IDOffset
}

func (tt *TraceTCP) SetWaitProbeFlag(waitProbe bool) {
	tt.Configuration.WaitProbe = waitProbe
}

func (tt *TraceTCP) GetWaitProbeFlag() bool {
	return tt.Configuration.WaitProbe
}

func (tt *TraceTCP) SetService(service string) {
	tt.Configuration.Service = service
}

func (tt *TraceTCP) SetStartWithEmptyPacket(start bool) {
	tt.Configuration.StartWithEmptyPacket = start
}
