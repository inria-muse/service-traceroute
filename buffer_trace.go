package tracetcp

import (
	"encoding/binary"
	"errors"
	"log"
	"math"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//Structure which manage the probing phase and analysis of the results for one traceroute
type BufferTrace struct {
	TransportProtocol string
	MaxTtl            int
	Iter              int
	InterProbe        int
	InterIter         int
	SendQ             chan []byte
	IPVersion         string
	R                 *Receiver
	FlowSeqMap        map[uint32]int64
	ProbeIdMap        map[uint16]int64
	ProbeSeqMap       map[uint16]int64
	E2eLatencies      []int64
	HopLatencies      map[uint16][]HopLatency

	BorderRouters       []net.IP
	BorderDistance      int
	ReachedBorderRouter bool
	BorderCheckChan     chan *CurrStatus
	Timeout             int

	MaxMissingHops        int
	ReachedMaxMissingHops bool

	IDOffset         uint16
	ProbingAlgorithm string

	ReachedFlowTimeout bool
	FlowEnded          bool
	DataTimeout        int
	LastPacketTime     int64

	StopAnalysis chan bool
	WaitAnalysis chan bool
	DoneSend     chan bool
	OutChan      chan string
	DoneExp      chan bool

	Buffer gopacket.SerializeBuffer

	StartTraceroutes bool
}

//Structure which contains the results
type HopLatency struct {
	Ip  string
	Rtt int64
}

//Initialize and configure a new buffer trace
func (bt *BufferTrace) NewBufferTrace(transportProtocol string, ipVersion string, r *Receiver, maxTTL int, numberIterations int, interProbeTime int, interIterationTime int, timeout int, idOffset uint16, probingAlgorithm string, flowTimeout int, startTraceroutes bool, maxConsecutiveMissingHops int, borderRouters []net.IP, sendQ chan []byte, outChan chan string) {
	bt.TransportProtocol = transportProtocol
	bt.IPVersion = ipVersion
	bt.MaxTtl = maxTTL
	bt.Iter = numberIterations
	bt.InterProbe = interProbeTime
	bt.InterIter = interIterationTime
	bt.Timeout = timeout
	bt.IDOffset = idOffset
	bt.ProbingAlgorithm = probingAlgorithm
	bt.MaxMissingHops = maxConsecutiveMissingHops
	bt.BorderRouters = borderRouters
	bt.SendQ = sendQ
	bt.R = r
	bt.ReachedBorderRouter = false
	bt.FlowSeqMap = make(map[uint32]int64)
	bt.ProbeIdMap = make(map[uint16]int64)
	bt.E2eLatencies = []int64{}
	bt.HopLatencies = make(map[uint16][]HopLatency)
	bt.DoneSend = make(chan bool)
	bt.WaitAnalysis = make(chan bool)
	bt.StopAnalysis = make(chan bool)
	bt.OutChan = outChan
	bt.DoneExp = make(chan bool)
	bt.BorderCheckChan = make(chan *CurrStatus, 100)
	bt.Buffer = gopacket.NewSerializeBuffer()
	bt.LastPacketTime = -1
	bt.DataTimeout = flowTimeout

	bt.StartTraceroutes = startTraceroutes
}

//Build and return a TCP IPv6 packets (not fully implemented)
func (bt *BufferTrace) BuildTCPIPv6(ttl int, id uint16, seqn uint32, ackn uint32) (layers.Ethernet, layers.IPv6, layers.IPv6Destination, layers.TCP) {
	ethernetLayer := layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := layers.IPv6{
		Version:    6,
		SrcIP:      bt.R.Curr.TCPLocalIp,
		DstIP:      bt.R.Curr.TCPRemIp,
		HopLimit:   uint8(ttl),
		NextHeader: layers.IPProtocolTCP,
	}

	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(id))

	ipDestinationOptionLayer := layers.IPv6DestinationOption{
		OptionLength: 64,
		OptionData:   buffer,

		// NextHeader:     layers.IPProtocolUDP,
		// Identification: uint32(id),
	}

	ipDestinationLayer := layers.IPv6Destination{
		Options: []*layers.IPv6DestinationOption{&ipDestinationOptionLayer},
	}

	tcpLayer := layers.TCP{
		DstPort:    layers.TCPPort(bt.R.Curr.RemPort),
		SrcPort:    layers.TCPPort(bt.R.Curr.LocalPort),
		DataOffset: 5,
		Seq:        uint32(seqn),
		Ack:        uint32(ackn),
		ACK:        true,
		Window:     0xffff,
	}
	return ethernetLayer, ipLayer, ipDestinationLayer, tcpLayer
}

//Build and return an UDP IPv6 packet (not fully implemented)
func (bt *BufferTrace) BuildUDPIPv6(ttl int, id uint16) (layers.Ethernet, layers.IPv6, layers.IPv6Destination, layers.UDP) {
	ethernetLayer := layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := layers.IPv6{
		Version:    6,
		SrcIP:      bt.R.Curr.TCPLocalIp,
		DstIP:      bt.R.Curr.TCPRemIp,
		HopLimit:   uint8(ttl),
		NextHeader: layers.IPProtocolUDP,
	}

	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(id))

	ipDestinationOptionLayer := layers.IPv6DestinationOption{
		OptionLength: 64,
		OptionData:   buffer,

		// NextHeader:     layers.IPProtocolUDP,
		// Identification: uint32(id),
	}

	ipDestinationLayer := layers.IPv6Destination{
		Options: []*layers.IPv6DestinationOption{&ipDestinationOptionLayer},
	}

	udpLayer := layers.UDP{
		DstPort: layers.UDPPort(bt.R.Curr.RemPort),
		SrcPort: layers.UDPPort(bt.R.Curr.LocalPort),
		Length:  8,
	}
	return ethernetLayer, ipLayer, ipDestinationLayer, udpLayer
}

//Build and return an UDP packet
func (bt *BufferTrace) BuildUDP(ttl int, id uint16) (layers.Ethernet, layers.IPv4, layers.UDP) {
	ethernetLayer := layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TOS:      0x10,
		Length:   40,
		TTL:      uint8(ttl),
		Id:       uint16(id),
		SrcIP:    bt.R.Curr.TCPLocalIp,
		DstIP:    bt.R.Curr.TCPRemIp,
		Protocol: layers.IPProtocolUDP,
	}

	udpLayer := layers.UDP{
		DstPort: layers.UDPPort(bt.R.Curr.RemPort),
		SrcPort: layers.UDPPort(bt.R.Curr.LocalPort),
		Length:  8,
	}
	return ethernetLayer, ipLayer, udpLayer
}

//Build and return a TCP packet
func (bt *BufferTrace) BuildTCP(ttl int, id uint16, seqn uint32, ackn uint32) (layers.Ethernet, layers.IPv4, layers.TCP) {
	ethernetLayer := layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TOS:      0x10,
		Length:   40,
		TTL:      uint8(ttl),
		Id:       uint16(id),
		SrcIP:    bt.R.Curr.TCPLocalIp,
		DstIP:    bt.R.Curr.TCPRemIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		DstPort:    layers.TCPPort(bt.R.Curr.RemPort),
		SrcPort:    layers.TCPPort(bt.R.Curr.LocalPort),
		DataOffset: 5,
		Seq:        uint32(seqn),
		Ack:        uint32(ackn),
		ACK:        true,
		Window:     0xffff,
	}
	return ethernetLayer, ipLayer, tcpLayer
}

//Encode a TCP packet and send it to sender for the final transmission on the interface
func (bt *BufferTrace) SendTCP(packetLayers []gopacket.SerializableLayer) {

	bt.Buffer.Clear()

	optsCSum := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	for i := len(packetLayers) - 1; i >= 0; i-- {
		layer := packetLayers[i]
		opts := gopacket.SerializeOptions{}

		if tcpL, ok := layer.(*layers.TCP); ok {
			if i == 0 {
				log.Fatal(errors.New("TCP layer without IP Layer"))
			}
			if bt.IPVersion == V4 {
				if ipL, ok := packetLayers[i-1].(*layers.IPv4); ok {
					if err := tcpL.SetNetworkLayerForChecksum(ipL); err != nil {
						log.Fatal(err)
					}
				}
			}
			if bt.IPVersion == V6 {
				if ip6L, ok := packetLayers[i-1].(*layers.IPv6); ok {
					if err := tcpL.SetNetworkLayerForChecksum(ip6L); err != nil {
						log.Fatal(err)
					}
				}
				if _, ok := packetLayers[i-1].(*layers.IPv6Destination); ok {
					if i-1 == 0 {
						log.Fatal(errors.New("TCP layer without IPv6 Layer"))
					}
					if ip6L, ok := packetLayers[i-2].(*layers.IPv6); ok {
						if err := tcpL.SetNetworkLayerForChecksum(ip6L); err != nil {
							log.Fatal(err)
						}
					}
				}
			}
			//TODO v6
			opts = optsCSum
		}
		if _, ok := layer.(*layers.IPv4); ok {
			opts = optsCSum
		}
		if _, ok := layer.(*layers.IPv6); ok {
			opts = optsCSum
		}
		if err := layer.SerializeTo(bt.Buffer, opts); err != nil {
			log.Fatal(err)
		}
	}

	bt.SendQ <- bt.Buffer.Bytes()
}

//Encode an UDP packet and send it to sender for the final transmission on the interface
func (bt *BufferTrace) SendUDP(packetLayers []gopacket.SerializableLayer) {
	bt.Buffer.Clear()

	optsCSum := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	for i := len(packetLayers) - 1; i >= 0; i-- {
		layer := packetLayers[i]
		opts := gopacket.SerializeOptions{}

		if udpL, ok := layer.(*layers.UDP); ok {
			if i == 0 {
				log.Fatal(errors.New("UDP layer without IP Layer"))
			}
			if bt.IPVersion == V4 {
				if ipL, ok := packetLayers[i-1].(*layers.IPv4); ok {
					if err := udpL.SetNetworkLayerForChecksum(ipL); err != nil {
						log.Fatal(err)
					}
				}
			}
			if bt.IPVersion == V6 {
				if ip6L, ok := packetLayers[i-1].(*layers.IPv6); ok {
					if err := udpL.SetNetworkLayerForChecksum(ip6L); err != nil {
						log.Fatal(err)
					}
				}
				if _, ok := packetLayers[i-1].(*layers.IPv6Destination); ok {
					if i-1 == 0 {
						log.Fatal(errors.New("UDP layer without IPv6 Layer"))
					}
					if ip6L, ok := packetLayers[i-2].(*layers.IPv6); ok {
						if err := udpL.SetNetworkLayerForChecksum(ip6L); err != nil {
							log.Fatal(err)
						}
					}
				}
			}

			//TODO v6
			opts = optsCSum
		}
		if _, ok := layer.(*layers.IPv4); ok {
			opts = optsCSum
		}
		if _, ok := layer.(*layers.IPv6); ok {
			opts = optsCSum
		}
		//TODO v6
		if err := layer.SerializeTo(bt.Buffer, opts); err != nil {
			log.Fatal(err)
		}
	}
	bt.SendQ <- bt.Buffer.Bytes()
}

//Start sending probes to the destination
func (bt *BufferTrace) StartProbing() {
	<-bt.R.SendStartChan

	bt.BorderDistance = bt.MaxTtl
	bt.ReachedFlowTimeout = false
	bt.FlowEnded = false
	iT := time.NewTicker(time.Microsecond * time.Duration(bt.InterIter))
	i := 1
	missingHops := 0
ProbingLoop:
	for _ = range iT.C {
		missingHops += 1
		//If DropProbes flag is enabled, stop the loop
		pT := time.NewTicker(time.Microsecond * time.Duration(bt.InterProbe))
		j := 0
		reachedBorder := false

		for _ = range pT.C {
			bt.ReachedFlowTimeout = !bt.IsFlowAlive()
			if bt.ReachedFlowTimeout || bt.FlowEnded {
				bt.BorderDistance = i
				break ProbingLoop
			}

			id := uint16(j*bt.MaxTtl + i - 1)

			if bt.IPVersion == V4 {
				if bt.TransportProtocol == Tcp {
					ethernetLayer, ipLayer, tcpLayer := bt.BuildTCP(i, bt.ConvertIDtoPktID(id), bt.R.Curr.Seq, bt.R.Curr.Ack)
					bt.SendTCP([]gopacket.SerializableLayer{&ethernetLayer, &ipLayer, &tcpLayer})
				} else if bt.TransportProtocol == Udp {
					ethernetLayer, ipLayer, udpLayer := bt.BuildUDP(i, bt.ConvertIDtoPktID(id))
					bt.SendUDP([]gopacket.SerializableLayer{&ethernetLayer, &ipLayer, &udpLayer})
				} else {
					log.Fatal(errors.New("Wrong transport protocol"))
				}
			} else if bt.IPVersion == V6 {
				if bt.TransportProtocol == Tcp {
					ethernetLayer, ipLayer, ipDestinationLayer, tcpLayer := bt.BuildTCPIPv6(i, bt.ConvertIDtoPktID(id), bt.R.Curr.Seq, bt.R.Curr.Ack)

					bt.SendTCP([]gopacket.SerializableLayer{&ethernetLayer, &ipLayer, &ipDestinationLayer, &tcpLayer})
				} else if bt.TransportProtocol == Udp {
					ethernetLayer, ipLayer, ipDestinationLayer, udpLayer := bt.BuildUDPIPv6(i, bt.ConvertIDtoPktID(id))
					bt.SendUDP([]gopacket.SerializableLayer{&ethernetLayer, &ipLayer, &ipDestinationLayer, &udpLayer})
				} else {
					log.Fatal(errors.New("Wrong transport protocol"))
				}
			}

			if bt.ProbingAlgorithm == PacketByPacket {
				reached, receivedReply := bt.WaitProbe(id)
				reachedBorder = reachedBorder || reached

				if receivedReply {
					missingHops = 0
				}
			}

			if bt.ProbingAlgorithm == Concurrent {
				missingHops = 0
			}

			j++
			if j >= bt.Iter {
				pT.Stop()
				break
			}

		}

		//Wait until we receive the #Iter of replies or until a timeout
		//What if we receive an old reply or wrong one? we may  keep the last IDs and check whether they corresponds or not
		//The check should be done in this thread to avoid problems and to avoid monitors

		//Or, I may use a chan of booleans, where AnalyzePackets insert False to say "go ahead, don't stop, it is not a border router" and True to say "stop, we reached a border router"
		//So:
		//Send #Iteration packets (or 1)
		//Wait that AnalyzePackets receives them
		//Wait that AnalyzePackets insert True/False (if the received IP matches one of the border routers) into the queue
		//If true, send next train of TTL

		if bt.ProbingAlgorithm == HopByHop {
			reached, receivedReply := bt.WaitTrain(uint16(i), bt.Iter)
			reachedBorder = reached

			if receivedReply {
				missingHops = 0
			}
		}

		i++

		if i > bt.MaxTtl || reachedBorder || (missingHops >= bt.MaxMissingHops && bt.MaxMissingHops > 0) {
			iT.Stop()
			bt.BorderDistance = i - 1
			if reachedBorder {
				bt.ReachedBorderRouter = true
			}
			if missingHops >= bt.MaxMissingHops {
				bt.ReachedMaxMissingHops = true
			}
			break
		}
	}

	if bt.ProbingAlgorithm == Concurrent {
		time.Sleep(time.Duration(bt.Timeout) * time.Millisecond)
	}
	bt.DoneSend <- true
}

//Return a flag specifying if the flow is alive or not
func (bt *BufferTrace) IsFlowAlive() bool {
	if bt.LastPacketTime < 0 || bt.DataTimeout <= 0 {
		return true
	}
	if int64(time.Now().UnixNano()-bt.LastPacketTime)/int64(time.Millisecond) > int64(bt.DataTimeout) {
		return false
	}
	return true
}

//Listen for all decoded packets from receiver in order to evaluate whether they are:
// - A probe, which define the starting time for the RTT
// - A reply (ICMP), which define the ending time for the RTT and the IP of the interface used to send the packet
// - Incoming or Outgoing packet, to check if the application flow is still alive (flow timeout) or it is closing (FIN - RST)
//From probes and replies it builds the final results: TTL - IP - RTT
func (bt *BufferTrace) AnalyzePackets() {
	defer func() {
		bt.WaitAnalysis <- true
	}()

	for {
		select {
		case <-bt.StopAnalysis:
			return
		case c := <-bt.R.FlowOutChan:
			bt.LastPacketTime = c.Ts
			bt.FlowSeqMap[c.Seq+c.IpDataLen-c.TcpHLen] = c.Ts

			if c.TcpFlags.RST || c.TcpFlags.FIN {
				bt.FlowEnded = true
			}
		case c := <-bt.R.FlowInChan:
			bt.LastPacketTime = c.Ts
			if c.TcpFlags.RST || c.TcpFlags.FIN {
				bt.FlowEnded = true
			}

			if sts, ok := bt.FlowSeqMap[c.Ack]; ok == true {
				bt.E2eLatencies = append(bt.E2eLatencies, c.Ts-sts)
				delete(bt.FlowSeqMap, c.Ack)
			}
		case c := <-bt.R.ProbeOutChan:
			id := bt.ConvertIDfromPktID(c.IpId)
			idMap := id % uint16(bt.MaxTtl)
			iter := id / uint16(bt.MaxTtl)

			if _, ok := bt.HopLatencies[idMap]; !ok {
				bt.HopLatencies[idMap] = make([]HopLatency, bt.Iter)
			}
			if oTs, ok := bt.ProbeIdMap[id]; ok {
				bt.HopLatencies[idMap][iter].Rtt = oTs - c.Ts
				delete(bt.ProbeIdMap, id)
			} else {
				bt.ProbeIdMap[id] = c.Ts
			}

		case c := <-bt.R.ProbeInChan:
			var id uint16 = bt.ConvertIDfromPktID(c.IpIdIcmp)

			c.IpId = id

			if id > uint16(bt.MaxTtl*bt.Iter) || id < 0 {
				continue
			}

			hIp := c.RemIp.String()
			hl := HopLatency{Ip: hIp, Rtt: 0}
			idMap := id % uint16(bt.MaxTtl)
			iter := id / uint16(bt.MaxTtl)

			if oTs, ok := bt.ProbeIdMap[id]; ok {
				hl.Rtt = c.Ts - oTs
				delete(bt.ProbeIdMap, id)
			} else {
				bt.ProbeIdMap[id] = c.Ts
			}

			if _, ok := bt.HopLatencies[idMap]; !ok {
				bt.HopLatencies[idMap] = make([]HopLatency, bt.Iter)
			}
			bt.HopLatencies[idMap][iter] = hl

			bt.BorderCheckChan <- &c
		}
	}
}

//Encode the results and configuration in a json format
func (bt *BufferTrace) PrintLatencies() TraceTCPReport {
	report := TraceTCPReport{}
	report.MaxTtl = bt.MaxTtl
	report.BorderDistance = bt.BorderDistance
	report.Iterations = bt.Iter
	report.InterIterationTime = bt.InterIter
	report.InterProbeTime = bt.InterProbe
	report.ReachedBorderRouter = bt.ReachedBorderRouter
	report.Hops = make([]string, bt.BorderDistance)
	report.HopIPs = make([][]string, bt.BorderDistance)
	report.Rtts = make([][]float64, bt.BorderDistance)
	report.RttsAvg = make([]float64, bt.BorderDistance)
	report.RttsVar = make([]float64, bt.BorderDistance)
	report.FlowTimeout = bt.DataTimeout
	report.ProbingAlgorithm = bt.ProbingAlgorithm
	report.ReachedBorderRouter = bt.ReachedBorderRouter
	report.ReachedFlowTimeout = bt.ReachedFlowTimeout
	report.MaxConsecutiveMissingHops = bt.MaxMissingHops
	report.ReachedMaxConsecutiveMissingHops = bt.ReachedMaxMissingHops
	report.Timeout = bt.Timeout
	report.FlowEnded = bt.FlowEnded

	for i := 0; i < bt.BorderDistance; i++ {
		if h, ok := bt.HopLatencies[uint16(i)]; ok {

			counter := 0
			var avg float64
			var avg2 float64

			report.HopIPs[i] = make([]string, 0)
			report.Rtts[i] = make([]float64, 0)

			for j := 0; j < bt.Iter; j++ {
				if h[j].Rtt > 0 {
					report.Hops[i] = h[j].Ip
					report.HopIPs[i] = append(report.HopIPs[i], h[j].Ip)
					report.Rtts[i] = append(report.Rtts[i], float64(h[j].Rtt)/float64(time.Millisecond))
					counter++
					avg += float64(h[j].Rtt) / float64(time.Millisecond)
					avg2 += math.Pow(float64(h[j].Rtt)/float64(time.Millisecond), 2)
				}
			}
			if counter > 0 {
				avg /= float64(counter)
				avg2 /= float64(counter)
			}
			report.RttsAvg[i] = avg
			report.RttsVar[i] = avg2 - math.Pow(avg, 2)
		}
	}
	return report
}

//Check if an IP is a border router
func (bt *BufferTrace) IsBorderRouter(ip net.IP) bool {
	//If border routers are not defined, then it is not necessary to check
	//The probes must be sent up to maximum distance
	if bt.BorderRouters == nil {
		return false
	}
	for _, borderIP := range bt.BorderRouters {
		if ip.String() == borderIP.String() {
			return true
		}
	}
	return false
}

//Wait the replies to all probes sent with the same TTL
//After a timeout, stop the waiting and return if a border router was detected
func (bt *BufferTrace) WaitTrain(ttl uint16, numberIterations int) (bool, bool) {
	border := false
	received := false
	start := time.Now()
	for i := 0; i < numberIterations; {
		select {
		case c := <-bt.BorderCheckChan:
			pktTTL := (c.IpId)%uint16(bt.MaxTtl) + 1

			//Check if it is an old reply or not
			if pktTTL != ttl {
				continue
			}
			//Check if border router
			//Using border OR isBorder simplify the management with booleans
			//Once border is true, it will remain true for the whole time
			border = border || bt.IsBorderRouter(c.RemIp)
			received = true

			//One packet has been analyzed correctly
			i++

		default:
			//Check if the timeout has elapsed or not
			elapsed := float64(time.Now().UnixNano()-start.UnixNano()) / float64(time.Millisecond)
			//If time elapsed
			if elapsed >= float64(bt.Timeout) {
				return border, received
			}

			time.Sleep(100 * time.Microsecond)
		}
	}
	return border, received
}

//Wait the reply to one probe
//After a timeout, stop the waiting and return if a border router was detected
func (bt *BufferTrace) WaitProbe(id uint16) (bool, bool) {
	border := false
	//Check if someone replied
	received := false
	start := time.Now()
	for {
		select {
		case c := <-bt.BorderCheckChan:
			//Check if it is an old reply or not
			if c.IpId != id {
				continue
			}
			//Check if border router
			//Using border OR isBorder simplify the management with booleans
			//Once border is true, it will remain true for the whole time
			border = border || bt.IsBorderRouter(c.RemIp)

			//Someone replied
			received = true
			//One packet has been analyzed correctly
			return border, received

		default:
			//Check if the timeout has elapsed or not
			elapsed := float64(time.Now().UnixNano()-start.UnixNano()) / float64(time.Millisecond)
			//If time elapsed
			if elapsed >= float64(bt.Timeout) {
				return border, received
			}
			time.Sleep(100 * time.Microsecond)
		}
	}
}

//Convert the ID of the probe to the real IPID to be used to distinguish all ICMP replies between the different traceroutes
func (bt *BufferTrace) ConvertIDtoPktID(id uint16) uint16 {
	sum := id + bt.IDOffset
	return sum
}

//Convert the IPID to the correct IP in order to get the correct iteration and TTL
func (bt *BufferTrace) ConvertIDfromPktID(pktID uint16) uint16 {
	sum := pktID - bt.IDOffset
	return sum
}

//Run the traceroute: start the analysis thread and then send the probes
func (bt *BufferTrace) Run() TraceTCPReport {
	if bt.StartTraceroutes {
		go bt.AnalyzePackets()
		go bt.StartProbing()
		<-bt.DoneSend
	}
	report := bt.PrintLatencies()
	report.TransportProtocol = bt.TransportProtocol
	if bt.StartTraceroutes {
		bt.StopAnalysis <- true
		<-bt.WaitAnalysis
	}
	return report
}
