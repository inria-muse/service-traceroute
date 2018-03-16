package main

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type BufferTrace struct {
	MaxTtl       int
	Iter         int
	InterProbe   int
	InterIter    int
	SendQ        chan []gopacket.SerializableLayer
	R            *Receiver
	FlowSeqMap   map[uint32]int64
	ProbeIdMap   map[uint16]int64
	ProbeSeqMap  map[uint16]int64
	E2eLatencies []int64
	HopLatencies map[uint16][]HopLatency

	BorderRouters   []net.IP
	BorderCheckChan chan CurrStatus
	Timeout         int

	IDOffset       uint16
	WaitProbeReply bool

	DoneSend chan bool
	OutChan  chan string
	DoneExp  chan bool
}

type HopLatency struct {
	Ip  string
	Rtt int64
}

func (bt *BufferTrace) NewBufferTrace(r *Receiver, maxTTL int, numberIterations int, interProbeTime int, interIterationTime int, timeout int, idOffset uint16, waitProbeReply bool, borderRouters []net.IP, sendQ chan []gopacket.SerializableLayer, outChan chan string) {
	bt.MaxTtl = maxTTL
	bt.Iter = numberIterations
	bt.InterProbe = interProbeTime
	bt.InterIter = interIterationTime
	bt.Timeout = timeout
	bt.IDOffset = idOffset
	bt.WaitProbeReply = waitProbeReply
	bt.BorderRouters = borderRouters
	bt.SendQ = sendQ
	bt.R = r
	bt.FlowSeqMap = make(map[uint32]int64)
	bt.ProbeIdMap = make(map[uint16]int64)
	bt.E2eLatencies = []int64{}
	bt.HopLatencies = make(map[uint16][]HopLatency)
	bt.DoneSend = make(chan bool)
	bt.OutChan = outChan
	bt.DoneExp = make(chan bool)
	bt.BorderCheckChan = make(chan CurrStatus, 1000)

	//bt.OutChan <- fmt.Sprintf("Offset of %d and maxttl of %d", bt.IDOffset, bt.MaxTtl)
}

func (bt *BufferTrace) BuildPkt() (layers.Ethernet, layers.IPv4, layers.TCP) {
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
		SrcIP:    bt.R.Curr.TCPLocalIp,
		DstIP:    bt.R.Curr.TCPRemIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		DstPort:    layers.TCPPort(bt.R.Curr.RemPort),
		SrcPort:    layers.TCPPort(bt.R.Curr.LocalPort),
		DataOffset: 5,
		Seq:        0,
		Ack:        0,
		ACK:        true,
		Window:     0xffff,
	}
	return ethernetLayer, ipLayer, tcpLayer
}

func (bt *BufferTrace) SendPkts() {
	<-bt.R.SendStartChan

	//bt.OutChan <- fmt.Sprintf("Sending probe iterations...")
	iT := time.NewTicker(time.Millisecond * time.Duration(bt.InterIter+bt.InterProbe*bt.MaxTtl))
	i := 1
	for _ = range iT.C {
		pT := time.NewTicker(time.Millisecond * time.Duration(bt.InterProbe))
		j := 0
		reachedBorder := false

		for _ = range pT.C {
			id := uint16(j*bt.MaxTtl + i - 1)

			ethernetLayer, ipLayer, tcpLayer := bt.BuildPkt()

			ipLayer.TTL = uint8(i)
			ipLayer.Id = bt.ConvertIDtoPktID(id)
			tcpLayer.Seq = bt.R.Curr.Seq
			tcpLayer.Ack = bt.R.Curr.Ack

			//bt.OutChan <- fmt.Sprintf("Sending probe TTL %d with ID = %d\n\tSeq %d\n\tAck %d", ipLayer.TTL, ipLayer.Id, tcpLayer.Seq, tcpLayer.Ack)
			bt.SendQ <- []gopacket.SerializableLayer{&ethernetLayer, &ipLayer, &tcpLayer}

			if bt.WaitProbeReply {
				reachedBorder = reachedBorder || bt.WaitProbeAndCheckForBorderRouter(id)
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

		if !bt.WaitProbeReply {
			reachedBorder = bt.WaitTrainAndCheckForBorderRouter(uint16(i), bt.Iter)
		}

		i++

		if i > bt.MaxTtl || reachedBorder {
			iT.Stop()
			break
		}
	}
	//bt.OutChan <- fmt.Sprintf("Done sending probes")
	bt.DoneSend <- true
}

func (bt *BufferTrace) AnalyzePackets() {
	for {
		select {
		case c := <-bt.R.FlowOutChan:
			bt.FlowSeqMap[c.Seq+c.IpDataLen-c.TcpHLen] = c.Ts
		case c := <-bt.R.FlowInChan:
			if sts, ok := bt.FlowSeqMap[c.Ack]; ok == true {
				bt.E2eLatencies = append(bt.E2eLatencies, c.Ts-sts)
				delete(bt.FlowSeqMap, c.Ack)
			}
		case c := <-bt.R.ProbeOutChan:
			//bt.OutChan <- fmt.Sprintf("Sent reply with ID = %d at time %d", c.IpId, c.Ts)
			c.IpId = bt.ConvertIDfromPktID(c.IpId)
			id := c.IpId
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
			var id uint16 = bt.ConvertIDfromPktID(binary.BigEndian.Uint16(c.IcmpPayload[4:6]))

			c.IpId = id

			if id > uint16(bt.MaxTtl*bt.Iter) || id < 0 {
				continue
			}

			//bt.OutChan <- fmt.Sprintf("Received reply with ID = %d at time %d\n", id, c.Ts)

			hIp := c.RemIp.String()
			hl := HopLatency{Ip: hIp, Rtt: 0}
			idMap := id % uint16(bt.MaxTtl)
			iter := id / uint16(bt.MaxTtl)

			//bt.OutChan <- fmt.Sprintf("Received reply with idMap = %d ( < %d) and iter = %d ( < %d )\n\tFrom %s\n", idMap, bt.MaxTtl, iter, bt.Iter, c.RemIp.String())

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

			bt.BorderCheckChan <- c
		}
	}
}

func (bt *BufferTrace) PrintLatencies() TraceTCPReport {
	report := TraceTCPReport{}
	report.ips = make([]string, 0)
	report.distance = make([]int, 0)
	report.rtts = make([]float32, 0)

	for i := 0; i < bt.MaxTtl; i++ {
		if h, ok := bt.HopLatencies[uint16(i)]; ok {
			for j := 0; j < bt.Iter; j++ {
				if h[j].Rtt != 0 {
					report.ips = append(report.ips, h[j].Ip)
					report.distance = append(report.distance, (i + 1))
					report.rtts = append(report.rtts, float32(h[j].Rtt)/float32(time.Millisecond))
				}
			}
		}
	}
	return report
}

func (bt *BufferTrace) Run() TraceTCPReport {
	//bt.OutChan <- fmt.Sprintf("%.3f: Starting buffertrace experiment", float64(time.Now().UnixNano())/float64(time.Second))
	go bt.AnalyzePackets()
	go bt.SendPkts()
	<-bt.DoneSend
	<-time.After(time.Second * 2)
	report := bt.PrintLatencies()
	bt.DoneExp <- true
	return report
}

func (bt *BufferTrace) IsBorderRouter(ip net.IP) bool {
	//If border routers are not define, then it is not necessary to check
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

func (bt *BufferTrace) WaitTrainAndCheckForBorderRouter(ttl uint16, numberIterations int) bool {
	border := false
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

			//One packet has been analyzed correctly
			i++

		default:
			//Check if the timeout has elapsed or not
			elapsed := float64(time.Now().UnixNano()-start.UnixNano()) / float64(time.Millisecond)
			//If time elapsed
			if elapsed >= float64(bt.Timeout) {
				//bt.OutChan <- fmt.Sprintf("Time elapsed")
				return border
			}
		}
	}
	//bt.OutChan <- fmt.Sprintf("%d - DONE", ttl)
	return border
}

func (bt *BufferTrace) WaitProbeAndCheckForBorderRouter(id uint16) bool {
	border := false
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

			//One packet has been analyzed correctly
			return border

		default:
			//Check if the timeout has elapsed or not
			elapsed := float64(time.Now().UnixNano()-start.UnixNano()) / float64(time.Millisecond)
			//If time elapsed
			if elapsed >= float64(bt.Timeout) {
				//bt.OutChan <- fmt.Sprintf("Time elapsed")
				return border
			}
		}
	}
}

func (bt *BufferTrace) ConvertIDtoPktID(id uint16) uint16 {
	sum := id + bt.IDOffset
	return sum
}

func (bt *BufferTrace) ConvertIDfromPktID(pktID uint16) uint16 {
	sum := pktID - bt.IDOffset
	return sum
}
