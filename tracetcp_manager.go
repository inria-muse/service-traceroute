package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"tcpmodule/tracetcp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//Lifetime of logs inside the map before the expiration
const LogTTL int64 = 180 //seconds?

//Interval for Offsets
//[start, end)
type OffsetInterval struct {
	start int //Start of the interval (included)
	end   int //End of the interval (not included)
}

//Configuration of TraceTCP Manager
type TraceTCPManagerConfiguration struct {
	Interface string   //Interface used to listen/send packets
	BorderIPs []net.IP //Router where traceTCP will stop (if flag is set to True)
	IPVersion string   //IP version

	InterIterationTime int //Time between each 'train' (packets with same TTL) of packets
	InterProbeTime     int //Time between each packet with same TTL

	Timeout int //How much time to wait before giving up (packet lost)
}

//Log of TraceTCP which will be stored in the map
type TraceTCPLog struct {
	Report        TraceTCPJson          //Final report, if traceTCP completed
	Configuration TraceTCPConfiguration //Configuration used for TraceTCP

	IsRunning  bool  //Flag to specify if it is running or not
	StartedAt  int64 //When TraceTCP started
	FinishedAt int64 //When TraceTCP finished (if not, then it is negative)
}

//Main struct for the manager of multiple TraceTCP
type TraceTCPManager struct {
	RunningTraceTCPs map[string]*TraceTCP //Contains all running experiments
	AvailableOffsets []OffsetInterval     //ID intervals available for new TraceTCPs

	//Configuration
	Configuration TraceTCPManagerConfiguration //Configuration of TraceTCP

	//Input Channels (captured packets)
	TCPChan  chan gopacket.Packet //Input channel for TCP packets to be forwarded to TraceTCP
	ICMPChan chan gopacket.Packet //Input channel for ICMP packets to be forwarded to TraceTCP

	//Output Channels
	OutPacketChan chan []gopacket.SerializableLayer //packets to be transmitted
	OutChan       chan string                       //data to be printed/stored

	//Channel to stop TraceTCPManager
	StopChan chan bool //To stop the manager

	//Local IPs
	LocalIPv4 net.IP //Local IPv4 of the machine running this library
	LocalIPv6 net.IP //Local IPv6 of the machine running this library

	//Mutex
	offsetMutex        *sync.Mutex //Mutex for offset array
	runningTracesMutex *sync.Mutex //Mutex for running TraceTCP array
	logsMapMutex       *sync.Mutex //Mutex for map with logs

	//Results
	LogsMap    map[string]TraceTCPLog //Contains the running experiments and the results of those finished in the last 3 minutes
	LogsMapTTL int64                  //time to live for data in logs map when the experiment is finished
}

//NewTraceTCPManager initialize the manager of multiple TraceTCP experiments
//iface string: is the name of the interface. It must be set
//ipVersion string: is the version of the IP layer ('4' or '6'). Use the const V4 or V6
//borderRouters []net.IP: are the IPs of the border routers, where TraceTCP will stop. It can be nil if not used
//return error: nil if no error happened during the initialization
func (tm *TraceTCPManager) NewTraceTCPManager(iface string, ipVersion string, borderRouters []net.IP) error {
	//Initial configuration
	tm.Configuration.Interface = iface
	tm.Configuration.IPVersion = ipVersion
	tm.Configuration.InterIterationTime = 100 //ms
	tm.Configuration.InterProbeTime = 20      //ms
	tm.Configuration.Timeout = 2000           //ms

	//Init
	tm.offsetMutex = &sync.Mutex{}
	tm.runningTracesMutex = &sync.Mutex{}
	tm.logsMapMutex = &sync.Mutex{}

	tm.RunningTraceTCPs = make(map[string]*TraceTCP)
	tm.AvailableOffsets = make([]OffsetInterval, 1)
	tm.LogsMap = make(map[string]TraceTCPLog)
	tm.LogsMapTTL = LogTTL

	//Add interval long all possible IDs
	tm.AvailableOffsets[0] = OffsetInterval{
		start: 0,
		end:   math.MaxUint16,
	}

	//Get local IPs
	err := tm.SetLocalIPs()

	if err != nil {
		return err
	}

	//Set borderRouters
	tm.Configuration.BorderIPs = borderRouters

	return nil
}

//Start the multiplexer for input packets. It forwards the input packets to the correct traceTCP
func (tm *TraceTCPManager) Run() {
	//Multiplexing of data between the running TraceTCPs and external process
	for {
		select {
		case <-tm.StopChan:
			return
		case tcpPacket := <-tm.TCPChan:
			ip1, port1, ip2, port2, err := tm.GetFlowIDFromTCPPacket(&tcpPacket)

			if err != nil {
				//ERROR: skip packet
				continue
			}

			tracetcp := tm.GetTraceTCPExperimentFromFlowID(ip1, port1, ip2, port2)

			if tracetcp == nil {
				//ERROR: skip packet
				continue
			}

			tracetcp.SniffChannel <- &tcpPacket

		case icmpPacket := <-tm.ICMPChan:
			dstIp, err := tm.GetDstIPFromICMPPacket(&icmpPacket)

			if err != nil {
				//ERROR: skip packet
				continue
			}

			tracetcp := tm.GetTraceTCPExperimentFromRemoteIP(dstIp)

			if tracetcp == nil || tracetcp.Configuration.RemoteIP.String() != dstIp.String() {
				//ERROR: skip packet
				continue
			}

			tracetcp.SniffChannel <- &icmpPacket
		}
	}
}

//Stop the multiplexer (Run() function)
func (tm *TraceTCPManager) Stop() {
	tm.StopChan <- true
}

//Open a new TraceTCP experiment
//Must be run on a thread, otherwise it locks the thread until the end
//If there is no space (i.e. no available offset spot), return error
func (tm *TraceTCPManager) StartNewConfiguredTraceTCP(remoteIP net.IP, remotePort int, service string, maxDistance int, numberIterations int, sniffing bool, canSendPkts bool, waitProbeReply bool, stopWithBorderRouters bool, startWithEmptyPacket bool) error {
	tm.ClearLogsMap()

	//check that there aren't any other TraceTCP to the same remote IP
	if tm.CheckExistanceTraceTCPExperiment(remoteIP) {
		return errors.New("TraceTCP to " + remoteIP.String() + " is already running")
	}

	//Check that there is enough space
	size := maxDistance * numberIterations
	interval, err := tm.UseInterval(size)

	//If it was not possible to get the interval, return error
	if err != nil {
		return err
	}

	borderIPs := tm.Configuration.BorderIPs

	//If the TraceTCP must not stop with border routers, just set the array to nil
	if !stopWithBorderRouters {
		borderIPs = nil
	}

	//Generate wanted configuration
	config := TraceTCPConfiguration{
		IDOffset:             uint16(interval.start),
		BorderIPs:            borderIPs,
		Service:              service,
		Distance:             maxDistance,
		Interface:            tm.Configuration.Interface,
		RemoteIP:             remoteIP,
		RemotePort:           remotePort,
		Sniffing:             sniffing,
		CanSendPackets:       canSendPkts,
		InterIterationTime:   tm.Configuration.InterIterationTime,
		InterProbeTime:       tm.Configuration.InterProbeTime,
		IPVersion:            tracetcp.V4,
		Iterations:           numberIterations,
		LocalIPv4:            tm.LocalIPv4,
		LocalIPv6:            tm.LocalIPv6,
		Timeout:              tm.Configuration.Timeout,
		WaitProbe:            waitProbeReply,
		StartWithEmptyPacket: startWithEmptyPacket,
	}

	log := TraceTCPLog{
		Configuration: config,
		IsRunning:     true,
		FinishedAt:    -1,
		StartedAt:     time.Now().UnixNano(),
	}

	//Start  TraceTCP on a new thread
	tracetcp := new(TraceTCP)
	tracetcp.NewConfiguredTraceTCP(config)

	//Set output channel
	tracetcp.SetOutPacketsChan(tm.OutPacketChan)

	//Set 'stdout'
	tracetcp.SetStdOutChan(tm.OutChan)

	//Check if there are no tracetcp to the same destination
	//If no tracetcp, then store tracetcp as running experiment
	exists := tm.CheckAndAddTraceTCPExperiment(tracetcp)

	if exists {
		//Free the used interval
		tm.FreeInterval(interval)
		return errors.New("TraceTCP to " + remoteIP.String() + " is already running")
	}

	tm.UpdateLogsMap(log)

	//Run TraceTCP
	report := tracetcp.Run()
	log.Report = report
	log.FinishedAt = time.Now().UnixNano()
	log.IsRunning = false

	tm.UpdateLogsMap(log)

	//Finished, remove tracetcp from running experiments
	tm.RemoveTraceTCPExperiment(tracetcp)

	//Free the used interval
	tm.FreeInterval(interval)

	return nil
}

//###### MUTEX REQUIRED #######

//Find the interval which fits for the given interval size
//Remove spot from the available spots in AvailableOffsets
func (tm *TraceTCPManager) UseInterval(size int) (OffsetInterval, error) {
	tm.offsetMutex.Lock()

	index := -1

	for i, interval := range tm.AvailableOffsets {
		if (interval.end - interval.start) >= size {
			index = i
			break
		}
	}

	//If no intervals are found
	if index < 0 {
		return OffsetInterval{}, errors.New("No offsets available for the required size")
	}

	interval := OffsetInterval{
		start: tm.AvailableOffsets[index].start,
		end:   tm.AvailableOffsets[index].start + size,
	}

	//Check if the interval must be removed or just resized
	if (tm.AvailableOffsets[index].end - tm.AvailableOffsets[index].start) == size {
		tm.AvailableOffsets = append(tm.AvailableOffsets[:index], tm.AvailableOffsets[:index+1]...)
	} else {
		tm.AvailableOffsets[index].start += size
	}

	tm.offsetMutex.Unlock()

	return interval, nil
}

//Add used spot to AvailableOffsets
func (tm *TraceTCPManager) FreeInterval(offsetInterval OffsetInterval) {
	tm.offsetMutex.Lock()

	for _, interval := range tm.AvailableOffsets {
		//The interval to be added was before 'interval'
		if offsetInterval.end == interval.start {
			interval.start = offsetInterval.end
			offsetInterval = interval
		}
		if offsetInterval.start == interval.end {
			interval.end = offsetInterval.start
			offsetInterval = interval
		}
	}

	tm.offsetMutex.Unlock()
}

//Check if there is an already running experiments
//However, if it says that there are no traceTCP to the remoteIP, it may happen  that
//a new experiment may be added immediately after it.
func (tm *TraceTCPManager) CheckExistanceTraceTCPExperiment(remoteIp net.IP) bool {
	exists := false

	tm.runningTracesMutex.Lock()

	if _, ok := tm.RunningTraceTCPs[remoteIp.String()]; ok {
		exists = true
	}

	tm.runningTracesMutex.Unlock()

	return exists
}

//Check if there is an already running experiments
//If not, it adds the given TraceTCP into the list of running experiments
func (tm *TraceTCPManager) CheckAndAddTraceTCPExperiment(tracetcp *TraceTCP) bool {
	exists := false

	tm.runningTracesMutex.Lock()

	if _, ok := tm.RunningTraceTCPs[tracetcp.Configuration.RemoteIP.String()]; ok {
		exists = true
	}

	if !exists {
		tm.RunningTraceTCPs[tracetcp.Configuration.RemoteIP.String()] = tracetcp
	}

	tm.runningTracesMutex.Unlock()
	return exists
}

//Remove the input tracetcp from the array of running experiments
func (tm *TraceTCPManager) RemoveTraceTCPExperiment(tracetcp *TraceTCP) {
	tm.runningTracesMutex.Lock()

	if _, ok := tm.RunningTraceTCPs[tracetcp.Configuration.RemoteIP.String()]; ok {
		delete(tm.RunningTraceTCPs, tracetcp.Configuration.RemoteIP.String())
	}

	tm.runningTracesMutex.Unlock()
}

//Return TraceTCP which contains the input IP ID
func (tm *TraceTCPManager) GetTraceTCPExperimentFromID(id uint16) *TraceTCP {
	tm.runningTracesMutex.Lock()

	var tracetcp *TraceTCP

	for _, runningTraceTCP := range tm.RunningTraceTCPs {
		size := uint16(runningTraceTCP.GetDistance() * runningTraceTCP.GetIterations())

		if id >= runningTraceTCP.GetIDOffset() && id < (runningTraceTCP.GetIDOffset()+size) {
			tracetcp = runningTraceTCP
			break
		}
	}

	tm.runningTracesMutex.Unlock()

	return tracetcp
}

//GetTraceTCPExperimentFromFlowID return the TraceTCP where remoteIP and remotePort matches one of 2 pairs given as input (where one is local end host and the other is the remote one)
func (tm *TraceTCPManager) GetTraceTCPExperimentFromFlowID(ip1 net.IP, port1 int, ip2 net.IP, port2 int) *TraceTCP {
	tm.runningTracesMutex.Lock()

	var tracetcp *TraceTCP

	for _, runningTraceTCP := range tm.RunningTraceTCPs {
		//Check if flows IDs corresponds (checking both directions)
		if runningTraceTCP.Configuration.RemoteIP.String() == ip1.String() && runningTraceTCP.Configuration.RemotePort == port1 {
			tracetcp = runningTraceTCP
			break
		} else if runningTraceTCP.Configuration.RemoteIP.String() == ip2.String() && runningTraceTCP.Configuration.RemotePort == port2 {
			tracetcp = runningTraceTCP
			break
		}
	}

	tm.runningTracesMutex.Unlock()

	return tracetcp
}

//GetTraceTCPExperimentFromRemoteIP return the TraceTCP which has the input remoteIP as destination
func (tm *TraceTCPManager) GetTraceTCPExperimentFromRemoteIP(remoteIP net.IP) *TraceTCP {
	tm.runningTracesMutex.Lock()

	var tracetcp *TraceTCP

	for _, runningTraceTCP := range tm.RunningTraceTCPs {
		//Check if flows IDs corresponds (checking both directions)
		if runningTraceTCP.Configuration.RemoteIP.String() == remoteIP.String() {
			tracetcp = runningTraceTCP
			break
		}
	}

	tm.runningTracesMutex.Unlock()

	return tracetcp
}

//Return the number of running TraceTCP
func (tm *TraceTCPManager) GetNumberOfRunningTraceTCP() int {
	tm.runningTracesMutex.Lock()

	numberRunningExps := len(tm.RunningTraceTCPs)

	tm.runningTracesMutex.Unlock()

	return numberRunningExps
}

//Return the log of a TraceTCP to remoteIP
func (tm *TraceTCPManager) GetLog(remoteIp string) (TraceTCPLog, error) {
	var log TraceTCPLog = TraceTCPLog{}
	var err error = nil

	tm.ClearLogsMap()

	tm.logsMapMutex.Lock()

	if _, ok := tm.LogsMap[remoteIp]; ok {
		log = tm.LogsMap[remoteIp]
	} else {
		err = errors.New("Log not found")
	}

	tm.logsMapMutex.Unlock()

	return log, err
}

//Remove old logs and add/update the input log
func (tm *TraceTCPManager) UpdateLogsMap(log TraceTCPLog) error {
	tm.ClearLogsMap()

	var err error = nil
	tm.logsMapMutex.Lock()

	tm.LogsMap[log.Configuration.RemoteIP.String()] = log

	tm.logsMapMutex.Unlock()
	return err
}

//Remove a given log from the map
func (tm *TraceTCPManager) RemoveLogsMap(log TraceTCPLog) error {
	var err error = nil

	if _, ok := tm.LogsMap[log.Configuration.RemoteIP.String()]; ok {
		delete(tm.LogsMap, log.Configuration.RemoteIP.String())
	} else {
		err = errors.New("Log not found")
	}

	return err
}

//Remove all old logs
func (tm *TraceTCPManager) ClearLogsMap() {
	tm.logsMapMutex.Lock()

	for _, v := range tm.LogsMap {
		now := time.Now().UnixNano()

		if v.FinishedAt <= 0 || v.IsRunning {
			continue
		}

		if ((now - v.FinishedAt) / int64(time.Second)) > tm.LogsMapTTL {
			tm.RemoveLogsMap(v)
		}
	}

	tm.logsMapMutex.Unlock()
}

//###### END MUTEX  #######

//###### PACKET PARSING  #######
//Get the Flow ID from a TCP packet
func (tm *TraceTCPManager) GetFlowIDFromTCPPacket(tcpPacket *gopacket.Packet) (net.IP, int, net.IP, int, error) {
	var ip1 net.IP
	var ip2 net.IP
	var port1 int
	var port2 int
	var err error

	if ip4Layer := (*tcpPacket).Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip1 = ip4Layer.(*layers.IPv4).SrcIP
		ip2 = ip4Layer.(*layers.IPv4).DstIP
	} else if ip6Layer := (*tcpPacket).Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip1 = ip6Layer.(*layers.IPv4).SrcIP
		ip2 = ip6Layer.(*layers.IPv4).DstIP
	} else {
		err = errors.New("No IPv4 Packet")
	}

	if tcpLayer := (*tcpPacket).Layer(layers.LayerTypeTCP); tcpLayer != nil {
		port1 = tm.ConvertPort(tcpLayer.(*layers.TCP).SrcPort.String())
		port2 = tm.ConvertPort(tcpLayer.(*layers.TCP).DstPort.String())
	} else {
		err = errors.New("No TCP Packet")
	}

	return ip1, port1, ip2, port2, err
}

//Return the IPID contained in the ICMP payload
func (tm *TraceTCPManager) GetIPIDFromICMPPacket(icmpPacket *gopacket.Packet) (uint16, error) {
	if icmp4Layer := (*icmpPacket).Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp, _ := icmp4Layer.(*layers.ICMPv4)

		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
			payload := make([]byte, len(icmp.LayerPayload()))
			copy(payload, icmp.LayerPayload())

			var id uint16 = binary.BigEndian.Uint16(payload[4:6])

			return id, nil
		}
	}
	return 0, errors.New("Not an ICMPv4 Packet")
}

//Return the final destination of traceTCP probe from the payload of ICMP
func (tm *TraceTCPManager) GetDstIPFromICMPPacket(icmpPacket *gopacket.Packet) (net.IP, error) {
	if icmp4Layer := (*icmpPacket).Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp, _ := icmp4Layer.(*layers.ICMPv4)

		if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded {
			// payload := make([]byte, len(icmp.LayerPayload()))
			// copy(payload, icmp.LayerPayload())

			ip := make(net.IP, 4)
			tmp := binary.BigEndian.Uint32(icmp.LayerPayload()[16:20])
			binary.BigEndian.PutUint32(ip, tmp)

			return ip, nil
		}
	}
	return nil, errors.New("Not an ICMPv4 Packet")
}

//###### END PACKET PARSING  #######

//###### GET & SET  #######

func (tm *TraceTCPManager) SetLocalIPs() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	validAddress := false

	for _, devIface := range devices {
		if devIface.Name == tm.Configuration.Interface {
			netIface, err := net.InterfaceByName(tm.Configuration.Interface)
			if err != nil {
				return err
			}
			addrs, _ := netIface.Addrs()
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.IsGlobalUnicast() && v.IP.To4() != nil {
						tm.LocalIPv4 = (*v).IP
						if tm.Configuration.IPVersion == V4 {
							validAddress = true
						}
					} else if v.IP.IsGlobalUnicast() && v.IP.To16() != nil {
						tm.LocalIPv6 = (*v).IP
						if tm.Configuration.IPVersion == V6 {
							fmt.Printf("Local V6 %s\n", v.IP.String())
							validAddress = true
						}
					}
				}
			}
		}
	}

	if !validAddress {
		return errors.New("No valid IP for interface")
	}
	return nil
}

func (tm *TraceTCPManager) SetBorderRouters(borderIPs []net.IP) {
	tm.Configuration.BorderIPs = borderIPs
}

func (tm *TraceTCPManager) AddBorderRouters(borderIPs ...net.IP) {
	tm.Configuration.BorderIPs = append(tm.Configuration.BorderIPs, borderIPs...)
}

func (tm *TraceTCPManager) GetBorderRouters() []net.IP {
	return tm.Configuration.BorderIPs
}

func (tm *TraceTCPManager) SetInterProbeTime(interProbeTime int) {
	tm.Configuration.InterProbeTime = interProbeTime
}

func (tm *TraceTCPManager) GetInterProbeTime() int {
	return tm.Configuration.InterProbeTime
}

func (tm *TraceTCPManager) SetInterInterationTime(interInterationTime int) {
	tm.Configuration.InterIterationTime = interInterationTime
}

func (tm *TraceTCPManager) GetInterInterationTime() int {
	return tm.Configuration.InterIterationTime
}

func (tm *TraceTCPManager) SetTimeout(timeout int) {
	tm.Configuration.Timeout = timeout
}

func (tm *TraceTCPManager) GetTimeout() int {
	return tm.Configuration.Timeout
}

func (tm *TraceTCPManager) SetOutChan(outchan chan string) {
	tm.OutChan = outchan
}

func (tm *TraceTCPManager) GetOutChan() chan string {
	return tm.OutChan
}

func (tm *TraceTCPManager) SetOutPktsChan(outPktsChan chan []gopacket.SerializableLayer) {
	tm.OutPacketChan = outPktsChan
}

func (tm *TraceTCPManager) GetOutPktsChan() chan []gopacket.SerializableLayer {
	return tm.OutPacketChan
}

func (tm *TraceTCPManager) SetICMPInChan(icmpChan chan gopacket.Packet) {
	tm.ICMPChan = icmpChan
}

func (tm *TraceTCPManager) SetTCPInChan(tcpChan chan gopacket.Packet) {
	tm.TCPChan = tcpChan
}

func (tm *TraceTCPManager) ConvertPort(port string) int {
	if !strings.Contains(port, "(") {
		p, _ := strconv.Atoi(port)
		return p
	}
	p, _ := strconv.Atoi(port[:strings.Index(port, "(")])
	return p
}
