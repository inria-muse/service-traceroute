package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"tcpmodule/tracetcp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//Interval for Offsets
//[start, end)
type OffsetInterval struct {
	start int //Start of the interval (included)
	end   int //End of the interval (not included)
}

type TraceTCPManagerConfiguration struct {
	Interface string
	BorderIPs []net.IP
	IPVersion string

	InterIterationTime int
	InterProbeTime     int

	Timeout int
}

type TraceTCPManager struct {
	RunningTraceTCPs []*TraceTCP
	AvailableOffsets []OffsetInterval

	//Configuration
	Configuration TraceTCPManagerConfiguration

	//Input Channels (captured packets)
	TCPChan  chan gopacket.Packet
	ICMPChan chan gopacket.Packet

	//Output Channels
	OutPacketChan chan []gopacket.SerializableLayer //packets to be transmitted
	OutChan       chan string                       //data to be printed/stored

	//Channel to stop TraceTCPManager
	StopChan chan bool

	//Local IPs
	LocalIPv4 net.IP
	LocalIPv6 net.IP

	//Mutex
	offsetMutex        *sync.Mutex
	runningTracesMutex *sync.Mutex
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

	tm.RunningTraceTCPs = make([]*TraceTCP, 0)
	tm.AvailableOffsets = make([]OffsetInterval, 1)

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

func (tm *TraceTCPManager) Run() {
	//Multiplexing of data between the running TraceTCPs and external process
	for {
		select {
		case <-tm.StopChan:
			return
		case tcpPacket := <-tm.TCPChan:
			id, err := tm.GetIPIDFromTCPPacket(tcpPacket)

			if err != nil {
				//ERROR
				continue
			}

			tracetcp := tm.GetTraceTCPExperimentFromID(id)

			tracetcp.InsertTCPPacket(tcpPacket)

		case icmpPacket := <-tm.ICMPChan:
			id, err := tm.GetIPIDFromICMPPacket(icmpPacket)

			if err != nil {
				//ERROR
				continue
			}

			tracetcp := tm.GetTraceTCPExperimentFromID(id)

			tracetcp.InsertICMPChannel(icmpPacket)
		}
	}
}

func (tm *TraceTCPManager) Stop() {
	tm.StopChan <- true
}

//Open a new TraceTCP experiment
//Must be run on a thread, otherwise it locks the thread until the end
//If there is no space (i.e. no available offset spot), return error
func (tm *TraceTCPManager) StartNewConfiguredTraceTCP(remoteIP net.IP, remotePort int, maxDistance int, numberIterations int, sniffing bool, canSendPkts bool, waitProbeReply bool, stopWithBorderRouters bool) error {
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
		IDOffset:           uint16(interval.start),
		BorderIPs:          borderIPs,
		Distance:           maxDistance,
		Interface:          tm.Configuration.Interface,
		RemoteIP:           remoteIP,
		RemotePort:         remotePort,
		Sniffing:           sniffing,
		CanSendPackets:     canSendPkts,
		InterIterationTime: tm.Configuration.InterIterationTime,
		InterProbeTime:     tm.Configuration.InterProbeTime,
		IPVersion:          tracetcp.V4,
		Iterations:         numberIterations,
		LocalIPv4:          tm.LocalIPv4,
		LocalIPv6:          tm.LocalIPv6,
		Timeout:            tm.Configuration.Timeout,
		WaitProbe:          waitProbeReply,
	}

	//Start  TraceTCP on a new thread
	tracetcp := new(TraceTCP)
	tracetcp.NewConfiguredTraceTCP(config)

	//Set 'stdout'
	tracetcp.SetStdOutChan(tm.OutChan)

	//Check if configuration for outgoing packets is correct
	if !canSendPkts && tm.OutPacketChan != nil {
		return errors.New("Undefined OutPacketChan. Cannot start TraceTCP with this settings")
	}

	//If requested, set redirect queue for outgoing pkts
	if !canSendPkts {
		tracetcp.SetOutPacketsChan(tm.OutPacketChan)
	}

	//Store tracetcp as running experiment
	tm.AddTraceTCPExperiment(tracetcp)

	//Run TraceTCP
	tracetcp.Run()

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

func (tm *TraceTCPManager) AddTraceTCPExperiment(tracetcp *TraceTCP) {
	tm.runningTracesMutex.Lock()
	tm.RunningTraceTCPs = append(tm.RunningTraceTCPs, tracetcp)
	tm.runningTracesMutex.Unlock()
}

func (tm *TraceTCPManager) RemoveTraceTCPExperiment(tracetcp *TraceTCP) {
	tm.runningTracesMutex.Lock()

	i := -1

	//Search the index of the experiment which finished
	for index, trace := range tm.RunningTraceTCPs {
		if trace == nil {
			continue
		}

		if tracetcp.Configuration.RemoteIP.String() == trace.Configuration.RemoteIP.String() {
			i = index
			break
		}
	}
	tm.OutChan <- fmt.Sprintf("Index to remove: %d", i)
	//Remove the experiment from the array
	tm.RunningTraceTCPs = append(tm.RunningTraceTCPs[:i], tm.RunningTraceTCPs[i+1:]...)

	tm.runningTracesMutex.Unlock()
}

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

func (tm *TraceTCPManager) GetNumberOfRunningTraceTCP() int {
	tm.runningTracesMutex.Lock()

	numberRunningExps := len(tm.RunningTraceTCPs)

	tm.runningTracesMutex.Unlock()

	return numberRunningExps
}

//###### END MUTEX  #######

//###### PACKET PARSING  #######

func (tm *TraceTCPManager) GetIPIDFromTCPPacket(tcpPacket gopacket.Packet) (uint16, error) {
	if ip4Layer := tcpPacket.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		id := ip4Layer.(*layers.IPv4).Id
		return id, nil
	}
	return 0, errors.New("No IPv4 Packet")
}

func (tm *TraceTCPManager) GetIPIDFromICMPPacket(icmpPacket gopacket.Packet) (uint16, error) {
	if icmp4Layer := icmpPacket.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		icmp, _ := icmp4Layer.(*layers.ICMPv4)
		payload := make([]byte, len(icmp.LayerPayload()))
		copy(payload, icmp.LayerPayload())

		var id uint16 = binary.BigEndian.Uint16(payload[4:6])

		return id, nil
	}
	return 0, errors.New("Not an ICMPv4 Packet")
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
