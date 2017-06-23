package main

import (
	"encoding/binary"
	"fmt"
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
	DoneSend     chan bool
	OutChan      chan string
}

type HopLatency struct {
	Ip  string
	Rtt int64
}

func (bt *BufferTrace) NewBufferTrace(r *Receiver, sendQ chan []gopacket.SerializableLayer, outChan chan string) {
	bt.MaxTtl = 32     //hardcoding for now
	bt.Iter = 10       //hardcoding for now
	bt.InterProbe = 10 //harcoding for now
	bt.InterIter = 100 //hardcoding for now
	bt.SendQ = sendQ
	bt.R = r
	bt.FlowSeqMap = make(map[uint32]int64)
	bt.ProbeIdMap = make(map[uint16]int64)
	bt.E2eLatencies = []int64{}
	bt.HopLatencies = make(map[uint16][]HopLatency)
	bt.DoneSend = make(chan bool)
	bt.OutChan = outChan
}

func (bt *BufferTrace) SendPkts() {
	<-bt.R.SendStartChan

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       bt.R.Curr.LocalHw,
		DstMAC:       bt.R.Curr.RemHw,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TOS:      0x10,
		Length:   40,
		SrcIP:    bt.R.Curr.TCPLocalIp,
		DstIP:    bt.R.Curr.TCPRemIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		DstPort:    layers.TCPPort(bt.R.Curr.RemPort),
		SrcPort:    layers.TCPPort(bt.R.Curr.LocalPort),
		DataOffset: 5,
		Seq:        0,
		Ack:        0,
		ACK:        true,
		Window:     0xffff,
	}
	bt.OutChan <- fmt.Sprintf("Sending probe iterations...")
	iT := time.NewTicker(time.Millisecond * time.Duration(bt.InterIter+bt.InterProbe*bt.MaxTtl))
	i := 0
	for _ = range iT.C {
		bt.OutChan <- fmt.Sprintf("\t%d...", i)
		pT := time.NewTicker(time.Millisecond * time.Duration(bt.InterProbe))
		j := 1
		for _ = range pT.C {
			ipLayer.TTL = uint8(j)
			ipLayer.Id = uint16(i*bt.MaxTtl + j)
			tcpLayer.Seq = bt.R.Curr.Seq
			tcpLayer.Ack = bt.R.Curr.Ack

			bt.SendQ <- []gopacket.SerializableLayer{ethernetLayer, ipLayer, tcpLayer}
			j++
			if j > bt.MaxTtl {
				pT.Stop()
				break
			}
		}
		i++
		if i == bt.Iter {
			iT.Stop()
			break
		}
	}
	bt.OutChan <- fmt.Sprintf("Done sending probes")
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
			bt.ProbeIdMap[c.IpId] = c.Ts
		case c := <-bt.R.ProbeInChan:
			var id uint16 = binary.BigEndian.Uint16(c.IcmpPayload[4:6])
			if oTs, ok := bt.ProbeIdMap[id]; ok {
				hIp := c.RemIp.String()
				hl := HopLatency{Ip: hIp, Rtt: c.Ts - oTs}
				idMap := id % uint16(bt.MaxTtl)
				iter := id / uint16(bt.MaxTtl)
				if iter > uint16(bt.Iter) {
					//log
				}
				if _, ok := bt.HopLatencies[idMap]; !ok {
					bt.HopLatencies[idMap] = make([]HopLatency, bt.Iter)
				}
				bt.HopLatencies[idMap][iter] = hl
				delete(bt.ProbeIdMap, id)
			}
		}
	}
}

func (bt *BufferTrace) PrintLatencies() {
	out := "\t\t====BufferTrace latencies====\n\n"
	blankOut := ""
	reachedDst := false
	for i := 1; i <= bt.MaxTtl; i++ {
		prevIp := ""
		if h, ok := bt.HopLatencies[uint16(i)]; ok {
			out += blankOut
			blankOut = ""
			out += fmt.Sprintf("%d\t", i)
			for j := 0; j < bt.Iter; j++ {
				if h[j].Rtt == 0 {
					out += "*\t"
				} else {
					if h[j].Ip != prevIp {
						prevIp = h[j].Ip
						out += fmt.Sprintf("(%s", prevIp)
						if h[j].Ip == bt.R.Curr.TCPRemIp.String() {
							out += fmt.Sprintf(" NAT")
							reachedDst = true
						}
						out += fmt.Sprintf(") ")
					}
					out += fmt.Sprintf("%.2f\t", float64(h[j].Rtt)/float64(time.Millisecond))
				}

			}
			out += "\n"
		} else {
			blankOut += fmt.Sprintf("%d\t*\n", i)
		}
	}
	if !reachedDst {
		out += blankOut
	}
	step := len(bt.E2eLatencies) / bt.Iter

	out += fmt.Sprintf("E2E\t")
	for i := 0; i < len(bt.E2eLatencies); i += step + 1 {
		out += fmt.Sprintf("%.2f\t", float64(bt.E2eLatencies[i])/float64(time.Millisecond))
	}
	out += "\n"
	bt.OutChan <- out
}

func (bt *BufferTrace) Run() {
	bt.OutChan <- fmt.Sprintf("%.3f: Starting buffertrace experiment", float64(time.Now().UnixNano())/float64(time.Millisecond))
	go bt.AnalyzePackets()
	go bt.SendPkts()
	<-bt.DoneSend
	<-time.After(time.Second * 2)
	bt.PrintLatencies()
}
